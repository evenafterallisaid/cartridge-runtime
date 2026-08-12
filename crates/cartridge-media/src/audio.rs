#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{MediaError, Result};

pub const SAMPLE_RATE: u32 = 48_000;
pub const CHANNELS: u16 = 2;
pub const MAX_AUDIO_NODES: usize = 128;
pub const MAX_AUDIO_EVENTS: usize = 65_536;
pub const MAX_AUDIO_FRAMES: u64 = SAMPLE_RATE as u64 * 30;
pub const MAX_AUDIO_WORK_UNITS: u64 = 100_000_000;
pub const MAX_AUDIO_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MIDI_EVENTS: usize = 4096;
pub const MAX_CAPTURED_AUDIO_RENDERS: usize = 64;
pub const MAX_CAPTURED_AUDIO_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DELAY_STORAGE_SAMPLES: u64 = MAX_AUDIO_FRAMES;
const MAX_FREQUENCY_MILLIHZ: i32 = 24_000_000;

#[derive(Clone, Copy, Debug)]
pub struct AudioLimits {
    pub max_nodes: usize,
    pub max_events: usize,
    pub max_frames: u64,
    pub max_work_units: u64,
}

impl Default for AudioLimits {
    fn default() -> Self {
        Self {
            max_nodes: MAX_AUDIO_NODES,
            max_events: MAX_AUDIO_EVENTS,
            max_frames: MAX_AUDIO_FRAMES,
            max_work_units: MAX_AUDIO_WORK_UNITS,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Waveform {
    Square,
    Saw,
    Triangle,
    Noise,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AudioNode {
    Oscillator {
        id: u16,
        waveform: Waveform,
        frequency_millihz: u32,
        level_q15: i16,
    },
    Gain {
        id: u16,
        input: u16,
        gain_q15: i16,
    },
    LowPass {
        id: u16,
        input: u16,
        coefficient_q15: u16,
    },
    Delay {
        id: u16,
        input: u16,
        delay_frames: u32,
        feedback_q15: i16,
        mix_q15: u16,
    },
    Output {
        id: u16,
        input: u16,
    },
}

impl AudioNode {
    fn id(&self) -> u16 {
        match self {
            Self::Oscillator { id, .. }
            | Self::Gain { id, .. }
            | Self::LowPass { id, .. }
            | Self::Delay { id, .. }
            | Self::Output { id, .. } => *id,
        }
    }
    fn input(&self) -> Option<u16> {
        match self {
            Self::Oscillator { .. } => None,
            Self::Gain { input, .. }
            | Self::LowPass { input, .. }
            | Self::Delay { input, .. }
            | Self::Output { input, .. } => Some(*input),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AudioParameter {
    FrequencyMillihz,
    LevelQ15,
    GainQ15,
    CoefficientQ15,
    FeedbackQ15,
    MixQ15,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterEvent {
    pub frame: u64,
    pub node: u16,
    pub parameter: AudioParameter,
    pub value: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AudioDocument {
    pub frames: u64,
    #[serde(default)]
    pub seed: u64,
    pub nodes: Vec<AudioNode>,
    #[serde(default)]
    pub events: Vec<ParameterEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AudioReceipt {
    pub frames: u64,
    pub sample_rate: u32,
    pub channels: u16,
    pub node_count: usize,
    pub event_count: usize,
    pub pcm_sha256: String,
    pub wav_sha256: String,
    pub peak: i16,
}

#[derive(Clone, Debug)]
pub struct AudioRender {
    pub receipt: AudioReceipt,
    pub pcm: Vec<i16>,
    pub wav: Vec<u8>,
}

pub fn render_audio_document(document: &[u8], limits: AudioLimits) -> Result<AudioRender> {
    if document.len() > MAX_AUDIO_DOCUMENT_BYTES {
        return Err(MediaError::Limit(format!(
            "audio document exceeds {MAX_AUDIO_DOCUMENT_BYTES} bytes"
        )));
    }
    let graph: AudioDocument =
        serde_json::from_slice(document).map_err(|error| MediaError::Invalid(error.to_string()))?;
    render_audio(&graph, limits)
}

pub fn render_audio(graph: &AudioDocument, limits: AudioLimits) -> Result<AudioRender> {
    validate_graph(graph, limits)?;
    let sample_count = usize::try_from(graph.frames)
        .ok()
        .and_then(|frames| frames.checked_mul(usize::from(CHANNELS)))
        .ok_or_else(|| MediaError::Limit("audio sample count overflows".into()))?;
    let mut pcm = Vec::with_capacity(sample_count);
    let mut states: Vec<NodeState> = graph
        .nodes
        .iter()
        .map(|node| NodeState::new(node, graph.seed))
        .collect::<Result<_>>()?;
    let output_index = graph.nodes.len() - 1;
    let mut event_index = 0usize;
    let mut peak = 0i16;
    for frame in 0..graph.frames {
        while graph
            .events
            .get(event_index)
            .is_some_and(|event| event.frame == frame)
        {
            apply_event(&mut states, &graph.events[event_index])?;
            event_index += 1;
        }
        let mut values = [0i32; MAX_AUDIO_NODES];
        for (index, state) in states.iter_mut().enumerate() {
            values[index] = state.sample(&values[..index]);
        }
        let sample = clamp_i16(values[output_index]);
        peak = peak.max(sample.saturating_abs());
        pcm.push(sample);
        pcm.push(sample);
    }
    let wav = encode_wav(&pcm, graph.frames)?;
    let receipt = AudioReceipt {
        frames: graph.frames,
        sample_rate: SAMPLE_RATE,
        channels: CHANNELS,
        node_count: graph.nodes.len(),
        event_count: graph.events.len(),
        pcm_sha256: hex_digest(&wav[44..]),
        wav_sha256: hex_digest(&wav),
        peak,
    };
    Ok(AudioRender { receipt, pcm, wav })
}

fn validate_graph(graph: &AudioDocument, limits: AudioLimits) -> Result<()> {
    if graph.frames == 0 || graph.frames > limits.max_frames || graph.frames > MAX_AUDIO_FRAMES {
        return Err(MediaError::Limit("audio frame limit exceeded".into()));
    }
    if graph.nodes.is_empty()
        || graph.nodes.len() > limits.max_nodes
        || graph.nodes.len() > MAX_AUDIO_NODES
    {
        return Err(MediaError::Limit("audio node limit exceeded".into()));
    }
    if graph.events.len() > limits.max_events || graph.events.len() > MAX_AUDIO_EVENTS {
        return Err(MediaError::Limit("audio event limit exceeded".into()));
    }
    let work = graph
        .frames
        .checked_mul(graph.nodes.len() as u64)
        .ok_or_else(|| MediaError::Limit("audio work estimate overflows".into()))?;
    if work > limits.max_work_units || work > MAX_AUDIO_WORK_UNITS {
        return Err(MediaError::Limit("audio work budget exceeded".into()));
    }
    let mut delay_samples = 0u64;
    for (index, node) in graph.nodes.iter().enumerate() {
        if usize::from(node.id()) != index {
            return Err(MediaError::Invalid(
                "audio node ids must be contiguous and ordered from zero".into(),
            ));
        }
        if node
            .input()
            .is_some_and(|input| usize::from(input) >= index)
        {
            return Err(MediaError::Invalid(format!(
                "node {} input must refer to an earlier node",
                node.id()
            )));
        }
        match node {
            AudioNode::Oscillator {
                frequency_millihz, ..
            } if *frequency_millihz > SAMPLE_RATE * 500 => {
                return Err(MediaError::Invalid(
                    "oscillator frequency exceeds Nyquist".into(),
                ));
            }
            AudioNode::Delay { delay_frames, .. } => {
                if *delay_frames == 0 || u64::from(*delay_frames) > limits.max_frames {
                    return Err(MediaError::Limit(
                        "delay length is outside the audio limits".into(),
                    ));
                }
                delay_samples = delay_samples.saturating_add(u64::from(*delay_frames));
                if delay_samples > MAX_DELAY_STORAGE_SAMPLES {
                    return Err(MediaError::Limit(
                        "aggregate delay storage limit exceeded".into(),
                    ));
                }
            }
            _ => {}
        }
    }
    if !matches!(graph.nodes.last(), Some(AudioNode::Output { .. })) {
        return Err(MediaError::Invalid(
            "the final audio node must be an output".into(),
        ));
    }
    let mut previous = 0;
    for (index, event) in graph.events.iter().enumerate() {
        if event.frame >= graph.frames || (index != 0 && event.frame < previous) {
            return Err(MediaError::Invalid(
                "audio events must be ordered and inside the render".into(),
            ));
        }
        previous = event.frame;
        if usize::from(event.node) >= graph.nodes.len() {
            return Err(MediaError::Invalid(format!(
                "audio event refers to unknown node {}",
                event.node
            )));
        }
        validate_parameter(&graph.nodes[usize::from(event.node)], event)?;
    }
    Ok(())
}

fn validate_parameter(node: &AudioNode, event: &ParameterEvent) -> Result<()> {
    let valid = match (node, event.parameter) {
        (AudioNode::Oscillator { .. }, AudioParameter::FrequencyMillihz) => {
            (0..=MAX_FREQUENCY_MILLIHZ).contains(&event.value)
        }
        (AudioNode::Oscillator { .. }, AudioParameter::LevelQ15)
        | (AudioNode::Gain { .. }, AudioParameter::GainQ15)
        | (AudioNode::Delay { .. }, AudioParameter::FeedbackQ15) => {
            i16::try_from(event.value).is_ok()
        }
        (AudioNode::LowPass { .. }, AudioParameter::CoefficientQ15)
        | (AudioNode::Delay { .. }, AudioParameter::MixQ15) => (0..=32767).contains(&event.value),
        _ => false,
    };
    if !valid {
        return Err(MediaError::Invalid(format!(
            "parameter {:?} is invalid for node {}",
            event.parameter, event.node
        )));
    }
    Ok(())
}

enum NodeState {
    Oscillator {
        id: u16,
        waveform: Waveform,
        phase: u32,
        increment: u32,
        level: i16,
        noise: u64,
    },
    Gain {
        id: u16,
        input: usize,
        gain: i16,
    },
    LowPass {
        id: u16,
        input: usize,
        coefficient: u16,
        previous: i32,
    },
    Delay {
        id: u16,
        input: usize,
        samples: Vec<i32>,
        cursor: usize,
        feedback: i16,
        mix: u16,
    },
    Output {
        id: u16,
        input: usize,
    },
}

impl NodeState {
    fn new(node: &AudioNode, seed: u64) -> Result<Self> {
        Ok(match node {
            AudioNode::Oscillator {
                id,
                waveform,
                frequency_millihz,
                level_q15,
            } => Self::Oscillator {
                id: *id,
                waveform: *waveform,
                phase: 0,
                increment: phase_increment(*frequency_millihz),
                level: *level_q15,
                noise: seed ^ u64::from(*id).wrapping_mul(0x9e37_79b9_7f4a_7c15),
            },
            AudioNode::Gain {
                id,
                input,
                gain_q15,
            } => Self::Gain {
                id: *id,
                input: usize::from(*input),
                gain: *gain_q15,
            },
            AudioNode::LowPass {
                id,
                input,
                coefficient_q15,
            } => Self::LowPass {
                id: *id,
                input: usize::from(*input),
                coefficient: *coefficient_q15,
                previous: 0,
            },
            AudioNode::Delay {
                id,
                input,
                delay_frames,
                feedback_q15,
                mix_q15,
            } => Self::Delay {
                id: *id,
                input: usize::from(*input),
                samples: vec![
                    0;
                    usize::try_from(*delay_frames).map_err(|_| MediaError::Limit(
                        "delay length is not addressable".into()
                    ))?
                ],
                cursor: 0,
                feedback: *feedback_q15,
                mix: *mix_q15,
            },
            AudioNode::Output { id, input } => Self::Output {
                id: *id,
                input: usize::from(*input),
            },
        })
    }

    fn id(&self) -> u16 {
        match self {
            Self::Oscillator { id, .. }
            | Self::Gain { id, .. }
            | Self::LowPass { id, .. }
            | Self::Delay { id, .. }
            | Self::Output { id, .. } => *id,
        }
    }

    fn sample(&mut self, values: &[i32]) -> i32 {
        match self {
            Self::Oscillator {
                waveform,
                phase,
                increment,
                level,
                noise,
                ..
            } => {
                let raw = match waveform {
                    Waveform::Square => {
                        if *phase < 0x8000_0000 {
                            32767
                        } else {
                            -32768
                        }
                    }
                    Waveform::Saw => ((*phase >> 16) as i32) - 32768,
                    Waveform::Triangle => {
                        let saw = ((*phase >> 16) as i32) - 32768;
                        32767 - (saw.unsigned_abs() as i32 * 2)
                    }
                    Waveform::Noise => {
                        *noise = noise
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        ((*noise >> 48) as i32) - 32768
                    }
                };
                *phase = phase.wrapping_add(*increment);
                q15(raw, i32::from(*level))
            }
            Self::Gain { input, gain, .. } => q15(values[*input], i32::from(*gain)),
            Self::LowPass {
                input,
                coefficient,
                previous,
                ..
            } => {
                *previous = previous.saturating_add(q15(
                    values[*input].saturating_sub(*previous),
                    i32::from(*coefficient),
                ));
                *previous
            }
            Self::Delay {
                input,
                samples,
                cursor,
                feedback,
                mix,
                ..
            } => {
                let delayed = samples[*cursor];
                let dry = values[*input];
                samples[*cursor] = dry.saturating_add(q15(delayed, i32::from(*feedback)));
                *cursor = (*cursor + 1) % samples.len();
                let wet = q15(delayed, i32::from(*mix));
                let dry_mix = q15(dry, 32767 - i32::from(*mix).min(32767));
                dry_mix.saturating_add(wet)
            }
            Self::Output { input, .. } => values[*input],
        }
    }
}

fn apply_event(states: &mut [NodeState], event: &ParameterEvent) -> Result<()> {
    let node = states
        .iter_mut()
        .find(|node| node.id() == event.node)
        .ok_or_else(|| MediaError::Invalid("event node disappeared".into()))?;
    match (node, event.parameter) {
        (NodeState::Oscillator { increment, .. }, AudioParameter::FrequencyMillihz)
            if (0..=MAX_FREQUENCY_MILLIHZ).contains(&event.value) =>
        {
            let frequency = u32::try_from(event.value)
                .map_err(|_| MediaError::Invalid("frequency parameter is negative".into()))?;
            *increment = phase_increment(frequency);
        }
        (NodeState::Oscillator { level, .. }, AudioParameter::LevelQ15) => {
            *level = checked_i16(event.value, "level")?;
        }
        (NodeState::Gain { gain, .. }, AudioParameter::GainQ15) => {
            *gain = checked_i16(event.value, "gain")?;
        }
        (NodeState::LowPass { coefficient, .. }, AudioParameter::CoefficientQ15) => {
            *coefficient = checked_u15(event.value, "coefficient")?;
        }
        (NodeState::Delay { feedback, .. }, AudioParameter::FeedbackQ15) => {
            *feedback = checked_i16(event.value, "feedback")?;
        }
        (NodeState::Delay { mix, .. }, AudioParameter::MixQ15) => {
            *mix = checked_u15(event.value, "mix")?;
        }
        _ => {
            return Err(MediaError::Invalid(format!(
                "parameter {:?} is invalid for node {}",
                event.parameter, event.node
            )));
        }
    }
    Ok(())
}

fn checked_i16(value: i32, name: &str) -> Result<i16> {
    i16::try_from(value)
        .map_err(|_| MediaError::Invalid(format!("{name} parameter is outside i16 range")))
}
fn checked_u15(value: i32, name: &str) -> Result<u16> {
    if (0..=32767).contains(&value) {
        u16::try_from(value)
            .map_err(|_| MediaError::Invalid(format!("{name} parameter is outside q15 range")))
    } else {
        Err(MediaError::Invalid(format!(
            "{name} parameter is outside q15 range"
        )))
    }
}
fn phase_increment(frequency_millihz: u32) -> u32 {
    ((u128::from(frequency_millihz) << 32) / (u128::from(SAMPLE_RATE) * 1000)) as u32
}
fn q15(value: i32, factor: i32) -> i32 {
    let product = i64::from(value) * i64::from(factor);
    (product / 32768).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}
fn clamp_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

fn encode_wav(pcm: &[i16], frames: u64) -> Result<Vec<u8>> {
    let pcm_bytes = pcm
        .len()
        .checked_mul(2)
        .ok_or_else(|| MediaError::Limit("wav data length overflows".into()))?;
    let data_len =
        u32::try_from(pcm_bytes).map_err(|_| MediaError::Limit("wav data exceeds 4 GiB".into()))?;
    let riff_len = 36u32
        .checked_add(data_len)
        .ok_or_else(|| MediaError::Limit("wav length overflows".into()))?;
    if frames
        .checked_mul(u64::from(CHANNELS))
        .and_then(|samples| samples.checked_mul(2))
        != Some(u64::from(data_len))
    {
        return Err(MediaError::Invalid(
            "pcm length does not match frame count".into(),
        ));
    }
    let mut wav = Vec::with_capacity(44 + pcm_bytes);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&riff_len.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&CHANNELS.to_le_bytes());
    wav.extend_from_slice(&SAMPLE_RATE.to_le_bytes());
    wav.extend_from_slice(&(SAMPLE_RATE * u32::from(CHANNELS) * 2).to_le_bytes());
    wav.extend_from_slice(&(CHANNELS * 2).to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    for sample in pcm {
        wav.extend_from_slice(&sample.to_le_bytes());
    }
    Ok(wav)
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug)]
pub struct RealtimeBuffer {
    samples: Box<[AtomicI32]>,
    read: AtomicUsize,
    write: AtomicUsize,
    underruns: AtomicU64,
    overruns: AtomicU64,
    peak_fill: AtomicUsize,
}

impl RealtimeBuffer {
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity < 2 || !capacity.is_power_of_two() || capacity > 1 << 22 {
            return Err(MediaError::Limit(
                "realtime buffer capacity must be a power of two between 2 and 4194304".into(),
            ));
        }
        Ok(Self {
            samples: (0..capacity).map(|_| AtomicI32::new(0)).collect(),
            read: AtomicUsize::new(0),
            write: AtomicUsize::new(0),
            underruns: AtomicU64::new(0),
            overruns: AtomicU64::new(0),
            peak_fill: AtomicUsize::new(0),
        })
    }

    pub fn push(&self, samples: &[i16]) -> usize {
        let mask = self.samples.len() - 1;
        let mut written = 0;
        for sample in samples {
            let write = self.write.load(Ordering::Relaxed);
            let next = write.wrapping_add(1) & mask;
            if next == self.read.load(Ordering::Acquire) {
                self.overruns.fetch_add(1, Ordering::Relaxed);
                break;
            }
            self.samples[write].store(i32::from(*sample), Ordering::Relaxed);
            self.write.store(next, Ordering::Release);
            written += 1;
            let fill = next.wrapping_sub(self.read.load(Ordering::Acquire)) & mask;
            self.peak_fill.fetch_max(fill, Ordering::Relaxed);
        }
        written
    }

    pub fn fill_callback(&self, output: &mut [i16]) {
        let mask = self.samples.len() - 1;
        for sample in output {
            let read = self.read.load(Ordering::Relaxed);
            if read == self.write.load(Ordering::Acquire) {
                *sample = 0;
                self.underruns.fetch_add(1, Ordering::Relaxed);
            } else {
                *sample = self.samples[read].load(Ordering::Relaxed) as i16;
                self.read
                    .store(read.wrapping_add(1) & mask, Ordering::Release);
            }
        }
    }

    #[must_use]
    pub fn telemetry(&self) -> AudioTelemetry {
        let mask = self.samples.len() - 1;
        let fill = self
            .write
            .load(Ordering::Acquire)
            .wrapping_sub(self.read.load(Ordering::Acquire))
            & mask;
        let latency_micros = u64::try_from(fill)
            .unwrap_or(u64::MAX)
            .saturating_mul(1_000_000)
            / (u64::from(SAMPLE_RATE) * u64::from(CHANNELS));
        AudioTelemetry {
            underruns: self.underruns.load(Ordering::Relaxed),
            overruns: self.overruns.load(Ordering::Relaxed),
            fill_samples: fill,
            peak_fill_samples: self.peak_fill.load(Ordering::Relaxed),
            capacity_samples: self.samples.len() - 1,
            estimated_latency_micros: latency_micros,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AudioTelemetry {
    pub underruns: u64,
    pub overruns: u64,
    pub fill_samples: usize,
    pub peak_fill_samples: usize,
    pub capacity_samples: usize,
    pub estimated_latency_micros: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AudioDevice {
    pub id: String,
    pub name: String,
    pub sample_rate: u32,
    pub channels: u16,
    pub is_default: bool,
}

#[derive(Clone, Debug)]
pub struct AudioDeviceCatalog {
    devices: Vec<AudioDevice>,
    generation: u64,
}

impl AudioDeviceCatalog {
    #[must_use]
    pub fn headless() -> Self {
        Self {
            devices: vec![AudioDevice {
                id: "headless".into(),
                name: "deterministic offline renderer".into(),
                sample_rate: SAMPLE_RATE,
                channels: CHANNELS,
                is_default: true,
            }],
            generation: 0,
        }
    }
    #[must_use]
    pub fn devices(&self) -> &[AudioDevice] {
        &self.devices
    }
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn replace(&mut self, devices: Vec<AudioDevice>) -> Result<()> {
        let mut ids = BTreeSet::new();
        if devices.len() > 256
            || devices.iter().filter(|device| device.is_default).count() > 1
            || devices.iter().any(|device| {
                device.id.is_empty()
                    || device.id.len() > 256
                    || device.name.len() > 256
                    || device.sample_rate == 0
                    || device.channels == 0
                    || !ids.insert(device.id.as_str())
            })
        {
            return Err(MediaError::Limit("audio device catalog is invalid".into()));
        }
        self.devices = devices;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| MediaError::Limit("audio device generation exhausted".into()))?;
        Ok(())
    }

    pub fn refresh(&mut self, provider: &impl AudioDeviceProvider) -> Result<()> {
        self.replace(provider.discover()?)
    }
}

pub trait AudioDeviceProvider {
    fn discover(&self) -> Result<Vec<AudioDevice>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HeadlessAudioDeviceProvider;

impl AudioDeviceProvider for HeadlessAudioDeviceProvider {
    fn discover(&self) -> Result<Vec<AudioDevice>> {
        Ok(AudioDeviceCatalog::headless().devices)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MidiEvent {
    pub timestamp_frames: u64,
    pub cable: u8,
    pub status: u8,
    pub data1: u8,
    pub data2: u8,
}

impl MidiEvent {
    pub fn validate(self) -> Result<Self> {
        if self.cable > 15 || self.status < 0x80 || self.data1 > 0x7f || self.data2 > 0x7f {
            return Err(MediaError::Invalid("invalid MIDI event".into()));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> AudioDocument {
        AudioDocument {
            frames: 4800,
            seed: 7,
            nodes: vec![
                AudioNode::Oscillator {
                    id: 0,
                    waveform: Waveform::Saw,
                    frequency_millihz: 440_000,
                    level_q15: 12_000,
                },
                AudioNode::LowPass {
                    id: 1,
                    input: 0,
                    coefficient_q15: 4000,
                },
                AudioNode::Output { id: 2, input: 1 },
            ],
            events: vec![ParameterEvent {
                frame: 2400,
                node: 0,
                parameter: AudioParameter::FrequencyMillihz,
                value: 660_000,
            }],
        }
    }

    #[test]
    fn offline_render_is_reproducible() {
        let first = render_audio(&graph(), AudioLimits::default()).unwrap();
        let second = render_audio(&graph(), AudioLimits::default()).unwrap();
        assert_eq!(first.receipt, second.receipt);
        assert_eq!(first.wav, second.wav);
    }

    #[test]
    fn graph_cycles_and_excess_work_are_rejected() {
        let mut value = graph();
        value.nodes[1] = AudioNode::Gain {
            id: 1,
            input: 9,
            gain_q15: 1,
        };
        assert!(render_audio(&value, AudioLimits::default()).is_err());
        let mut value = graph();
        value.frames = MAX_AUDIO_FRAMES;
        assert!(
            render_audio(
                &value,
                AudioLimits {
                    max_work_units: 1,
                    ..AudioLimits::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn callback_uses_preallocated_storage() {
        let ring = RealtimeBuffer::new(8).unwrap();
        assert_eq!(ring.push(&[1, 2, 3]), 3);
        let mut output = [0; 5];
        ring.fill_callback(&mut output);
        assert_eq!(output, [1, 2, 3, 0, 0]);
        assert_eq!(ring.telemetry().underruns, 2);
        assert_eq!(ring.telemetry().fill_samples, 0);
    }

    #[test]
    fn device_replacement_does_not_touch_render_state() {
        let expected = render_audio(&graph(), AudioLimits::default())
            .unwrap()
            .receipt;
        let mut catalog = AudioDeviceCatalog::headless();
        catalog.replace(Vec::new()).unwrap();
        catalog.refresh(&HeadlessAudioDeviceProvider).unwrap();
        assert_eq!(catalog.devices().len(), 1);
        assert_eq!(
            render_audio(&graph(), AudioLimits::default())
                .unwrap()
                .receipt,
            expected
        );
    }

    #[test]
    fn aggregate_delay_storage_is_bounded_before_allocation() {
        let mut nodes = vec![AudioNode::Oscillator {
            id: 0,
            waveform: Waveform::Square,
            frequency_millihz: 1,
            level_q15: 1,
        }];
        for id in 1..=3 {
            nodes.push(AudioNode::Delay {
                id,
                input: id - 1,
                delay_frames: u32::try_from(MAX_AUDIO_FRAMES / 2).unwrap(),
                feedback_q15: 0,
                mix_q15: 0,
            });
        }
        nodes.push(AudioNode::Output { id: 4, input: 3 });
        let document = AudioDocument {
            frames: 1,
            seed: 0,
            nodes,
            events: Vec::new(),
        };
        assert!(render_audio(&document, AudioLimits::default()).is_err());
    }
}
