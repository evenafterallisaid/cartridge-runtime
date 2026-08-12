#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::{collections::BTreeMap, io::Cursor};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{MediaError, Result};

pub const MAX_WINDOWS: usize = 8;
pub const MAX_DIMENSION: u32 = 4096;
pub const MAX_PIXELS: usize = 4 * 1024 * 1024;
pub const MAX_DRAW_COMMANDS: usize = 32_768;
pub const MAX_GRAPHICS_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_GRAPHICS_ASSET_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_WINDOW_TITLE_BYTES: usize = 256;
pub const MAX_CAPTURED_FRAMES: usize = 256;
pub const MAX_CAPTURED_GRAPHICS_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DRAW_WORK_UNITS: u64 = 100_000_000;
pub const MAX_LOGICAL_DIMENSION: u32 = 1_000_000;
pub const MAX_MEDIA_ASSET_PATH_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub struct GraphicsLimits {
    pub max_windows: usize,
    pub max_pixels: usize,
    pub max_commands: usize,
    pub max_asset_bytes: usize,
}

impl Default for GraphicsLimits {
    fn default() -> Self {
        Self {
            max_windows: MAX_WINDOWS,
            max_pixels: MAX_PIXELS,
            max_commands: MAX_DRAW_COMMANDS,
            max_asset_bytes: MAX_GRAPHICS_ASSET_BYTES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowConfig {
    pub title: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    #[serde(default = "opaque")]
    pub a: u8,
}

const fn opaque() -> u8 {
    u8::MAX
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DrawCommand {
    Clear {
        color: Color,
    },
    Rect {
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        color: Color,
    },
    Line {
        x1: i32,
        y1: i32,
        x2: i32,
        y2: i32,
        width: u16,
        color: Color,
    },
    Image {
        asset: String,
        source_width: u32,
        source_height: u32,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
    },
    Text {
        text: String,
        font: Option<String>,
        x: i32,
        y: i32,
        scale: u16,
        color: Color,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrameDocument {
    pub logical_width: u32,
    pub logical_height: u32,
    pub simulation_tick: u64,
    pub commands: Vec<DrawCommand>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FrameReceipt {
    pub window: u32,
    pub frame: u64,
    pub simulation_tick: u64,
    pub width: u32,
    pub height: u32,
    pub command_count: usize,
    pub rgba_sha256: String,
    pub png_sha256: String,
}

#[derive(Clone, Debug)]
pub struct RenderedFrame {
    pub receipt: FrameReceipt,
    pub rgba: Vec<u8>,
    pub png: Vec<u8>,
}

#[derive(Clone, Debug)]
struct VirtualWindow {
    config: WindowConfig,
    next_frame: u64,
    last_tick: Option<u64>,
}

#[derive(Debug)]
pub struct HeadlessDisplay {
    limits: GraphicsLimits,
    windows: BTreeMap<u32, VirtualWindow>,
    next_window: u32,
    frames: Vec<RenderedFrame>,
    captured_bytes: usize,
}

impl HeadlessDisplay {
    #[must_use]
    pub fn new(mut limits: GraphicsLimits) -> Self {
        limits.max_windows = limits.max_windows.min(MAX_WINDOWS);
        limits.max_pixels = limits.max_pixels.min(MAX_PIXELS);
        limits.max_commands = limits.max_commands.min(MAX_DRAW_COMMANDS);
        limits.max_asset_bytes = limits.max_asset_bytes.min(MAX_GRAPHICS_ASSET_BYTES);
        Self {
            limits,
            windows: BTreeMap::new(),
            next_window: 1,
            frames: Vec::new(),
            captured_bytes: 0,
        }
    }

    pub fn open(&mut self, config: WindowConfig) -> Result<u32> {
        validate_window(&config, self.limits)?;
        if self.windows.len() == self.limits.max_windows {
            return Err(MediaError::Limit("window limit reached".into()));
        }
        let handle = self.next_window;
        self.next_window = self
            .next_window
            .checked_add(1)
            .ok_or_else(|| MediaError::Limit("window handle space exhausted".into()))?;
        self.windows.insert(
            handle,
            VirtualWindow {
                config,
                next_frame: 0,
                last_tick: None,
            },
        );
        Ok(handle)
    }

    pub fn close(&mut self, window: u32) -> Result<()> {
        self.windows
            .remove(&window)
            .ok_or_else(|| MediaError::Invalid("unknown window handle".into()))?;
        Ok(())
    }

    pub fn resize(&mut self, window: u32, width: u32, height: u32) -> Result<()> {
        let candidate = WindowConfig {
            title: String::new(),
            width,
            height,
        };
        validate_window(&candidate, self.limits)?;
        let state = self
            .windows
            .get_mut(&window)
            .ok_or_else(|| MediaError::Invalid("unknown window handle".into()))?;
        state.config.width = width;
        state.config.height = height;
        Ok(())
    }

    pub fn present<'a, F>(&mut self, window: u32, document: &[u8], asset: F) -> Result<FrameReceipt>
    where
        F: FnMut(&str) -> Option<&'a [u8]>,
    {
        if self.frames.len() == MAX_CAPTURED_FRAMES
            || self.captured_bytes >= MAX_CAPTURED_GRAPHICS_BYTES
        {
            return Err(MediaError::Limit(
                "captured graphics output limit exceeded".into(),
            ));
        }
        if document.len() > MAX_GRAPHICS_DOCUMENT_BYTES {
            return Err(MediaError::Limit(format!(
                "graphics document exceeds {MAX_GRAPHICS_DOCUMENT_BYTES} bytes"
            )));
        }
        let frame: FrameDocument = serde_json::from_slice(document)
            .map_err(|error| MediaError::Invalid(error.to_string()))?;
        let state = self
            .windows
            .get(&window)
            .ok_or_else(|| MediaError::Invalid("unknown window handle".into()))?;
        if state
            .last_tick
            .is_some_and(|tick| frame.simulation_tick < tick)
        {
            return Err(MediaError::Invalid(
                "simulation ticks must be monotonic".into(),
            ));
        }
        let rendered = render_frame(
            window,
            state.next_frame,
            &state.config,
            &frame,
            self.limits,
            asset,
        )?;
        let artifact_bytes = rendered
            .rgba
            .len()
            .checked_add(rendered.png.len())
            .ok_or_else(|| MediaError::Limit("captured frame size overflows".into()))?;
        let next_captured = self
            .captured_bytes
            .checked_add(artifact_bytes)
            .ok_or_else(|| MediaError::Limit("captured graphics size overflows".into()))?;
        if self.frames.len() == MAX_CAPTURED_FRAMES || next_captured > MAX_CAPTURED_GRAPHICS_BYTES {
            self.captured_bytes = MAX_CAPTURED_GRAPHICS_BYTES;
            return Err(MediaError::Limit(
                "captured graphics output limit exceeded".into(),
            ));
        }
        let receipt = rendered.receipt.clone();
        let state = self
            .windows
            .get_mut(&window)
            .ok_or_else(|| MediaError::Invalid("window closed during presentation".into()))?;
        state.next_frame = state
            .next_frame
            .checked_add(1)
            .ok_or_else(|| MediaError::Limit("frame counter exhausted".into()))?;
        state.last_tick = Some(frame.simulation_tick);
        self.frames.push(rendered);
        self.captured_bytes = next_captured;
        Ok(receipt)
    }

    pub fn take_frames(&mut self) -> Vec<RenderedFrame> {
        self.captured_bytes = 0;
        std::mem::take(&mut self.frames)
    }
}

fn validate_window(config: &WindowConfig, limits: GraphicsLimits) -> Result<()> {
    if config.title.len() > MAX_WINDOW_TITLE_BYTES || config.title.chars().any(char::is_control) {
        return Err(MediaError::Invalid(
            "window title is too long or contains control characters".into(),
        ));
    }
    if config.width == 0
        || config.height == 0
        || config.width > MAX_DIMENSION
        || config.height > MAX_DIMENSION
    {
        return Err(MediaError::Limit(format!(
            "window dimensions must be between 1 and {MAX_DIMENSION}"
        )));
    }
    let pixels = usize::try_from(config.width)
        .ok()
        .and_then(|width| {
            usize::try_from(config.height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .ok_or_else(|| MediaError::Limit("window dimensions overflow".into()))?;
    if pixels > limits.max_pixels {
        return Err(MediaError::Limit("window pixel limit exceeded".into()));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn render_frame<'a, F>(
    window: u32,
    number: u64,
    config: &WindowConfig,
    frame: &FrameDocument,
    limits: GraphicsLimits,
    mut asset: F,
) -> Result<RenderedFrame>
where
    F: FnMut(&str) -> Option<&'a [u8]>,
{
    if frame.logical_width == 0 || frame.logical_height == 0 {
        return Err(MediaError::Invalid(
            "logical dimensions must be positive".into(),
        ));
    }
    if frame.logical_width > MAX_LOGICAL_DIMENSION || frame.logical_height > MAX_LOGICAL_DIMENSION {
        return Err(MediaError::Limit("logical dimensions are too large".into()));
    }
    if frame.commands.len() > limits.max_commands {
        return Err(MediaError::Limit("draw command limit exceeded".into()));
    }
    let pixels = usize::try_from(config.width)
        .ok()
        .and_then(|width| {
            usize::try_from(config.height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| MediaError::Limit("frame buffer size overflow".into()))?;
    let mut rgba = vec![0; pixels];
    let scale = Scale {
        logical_width: frame.logical_width,
        logical_height: frame.logical_height,
        width: config.width,
        height: config.height,
    };
    validate_draw_work(frame, scale, config)?;
    for command in &frame.commands {
        match command {
            DrawCommand::Clear { color } => clear(&mut rgba, *color),
            DrawCommand::Rect {
                x,
                y,
                width,
                height,
                color,
            } => fill_rect(
                &mut rgba,
                config.width,
                config.height,
                scale,
                *x,
                *y,
                *width,
                *height,
                *color,
            ),
            DrawCommand::Line {
                x1,
                y1,
                x2,
                y2,
                width,
                color,
            } => draw_line(
                &mut rgba,
                config.width,
                config.height,
                scale,
                (*x1, *y1),
                (*x2, *y2),
                *width,
                *color,
            ),
            DrawCommand::Image {
                asset: path,
                source_width,
                source_height,
                x,
                y,
                width,
                height,
            } => {
                validate_asset_path(path)?;
                if *source_width == 0 || *source_height == 0 {
                    return Err(MediaError::Asset(
                        "image dimensions must be positive".into(),
                    ));
                }
                let bytes = asset(path)
                    .ok_or_else(|| MediaError::Asset(format!("missing image asset {path:?}")))?;
                let expected = checked_rgba_len(*source_width, *source_height)?;
                if bytes.len() != expected || bytes.len() > limits.max_asset_bytes {
                    return Err(MediaError::Asset(format!(
                        "image asset {path:?} has an invalid length"
                    )));
                }
                blit(
                    &mut rgba,
                    config.width,
                    config.height,
                    scale,
                    bytes,
                    *source_width,
                    *source_height,
                    *x,
                    *y,
                    *width,
                    *height,
                )?;
            }
            DrawCommand::Text {
                text,
                font,
                x,
                y,
                scale: text_scale,
                color,
            } => {
                if text.len() > 16 * 1024 || *text_scale == 0 || *text_scale > 256 {
                    return Err(MediaError::Limit("text command exceeds its limits".into()));
                }
                if let Some(path) = font {
                    validate_asset_path(path)?;
                }
                let font_bytes = font
                    .as_ref()
                    .map(|path| {
                        asset(path).ok_or_else(|| {
                            MediaError::Asset(format!("missing font asset {path:?}"))
                        })
                    })
                    .transpose()?;
                draw_text(
                    &mut rgba,
                    config.width,
                    config.height,
                    scale,
                    text,
                    font_bytes,
                    *x,
                    *y,
                    *text_scale,
                    *color,
                )?;
            }
        }
    }
    let png = encode_png(config.width, config.height, &rgba)?;
    let receipt = FrameReceipt {
        window,
        frame: number,
        simulation_tick: frame.simulation_tick,
        width: config.width,
        height: config.height,
        command_count: frame.commands.len(),
        rgba_sha256: hex_digest(&rgba),
        png_sha256: hex_digest(&png),
    };
    Ok(RenderedFrame { receipt, rgba, png })
}

#[derive(Clone, Copy)]
struct Scale {
    logical_width: u32,
    logical_height: u32,
    width: u32,
    height: u32,
}

impl Scale {
    fn x(self, value: i32) -> i32 {
        scale_coordinate(value, self.width, self.logical_width)
    }
    fn y(self, value: i32) -> i32 {
        scale_coordinate(value, self.height, self.logical_height)
    }
    fn w(self, value: u32) -> u32 {
        scale_length(value, self.width, self.logical_width)
    }
    fn h(self, value: u32) -> u32 {
        scale_length(value, self.height, self.logical_height)
    }
}

fn scale_coordinate(value: i32, target: u32, logical: u32) -> i32 {
    let scaled = i64::from(value) * i64::from(target) / i64::from(logical);
    scaled.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

fn scale_length(value: u32, target: u32, logical: u32) -> u32 {
    let scaled = u64::from(value) * u64::from(target) / u64::from(logical);
    u32::try_from(scaled).unwrap_or(u32::MAX)
}

fn validate_draw_work(frame: &FrameDocument, scale: Scale, config: &WindowConfig) -> Result<()> {
    let canvas = u64::from(config.width) * u64::from(config.height);
    let mut work = 0u64;
    for command in &frame.commands {
        let command_work = match command {
            DrawCommand::Clear { .. } => canvas,
            DrawCommand::Rect { width, height, .. } | DrawCommand::Image { width, height, .. } => {
                u64::from(scale.w(*width).min(config.width))
                    .saturating_mul(u64::from(scale.h(*height).min(config.height)))
            }
            DrawCommand::Line {
                x1,
                y1,
                x2,
                y2,
                width,
                ..
            } => {
                if *width == 0 || *width > 64 {
                    return Err(MediaError::Limit(
                        "line width must be between 1 and 64".into(),
                    ));
                }
                validate_coordinate(*x1, frame.logical_width)?;
                validate_coordinate(*x2, frame.logical_width)?;
                validate_coordinate(*y1, frame.logical_height)?;
                validate_coordinate(*y2, frame.logical_height)?;
                let length = u64::from(scale.x(*x1).abs_diff(scale.x(*x2)))
                    .max(u64::from(scale.y(*y1).abs_diff(scale.y(*y2))))
                    .saturating_add(1);
                let brush = u64::from(*width).saturating_add(1);
                length.saturating_mul(brush.saturating_mul(brush))
            }
            DrawCommand::Text {
                text,
                font,
                x,
                y,
                scale: text_scale,
                ..
            } => {
                validate_coordinate(*x, frame.logical_width)?;
                validate_coordinate(*y, frame.logical_height)?;
                let characters = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
                let glyph_pixel = u64::from(scale.w(u32::from(*text_scale)).max(1))
                    .saturating_mul(u64::from(scale.h(u32::from(*text_scale)).max(1)));
                let raster = characters
                    .saturating_mul(16 * 32)
                    .saturating_mul(glyph_pixel);
                let font_decode = if font.is_some() { 95 * 16 * 32 } else { 0 };
                raster.saturating_add(font_decode)
            }
        };
        work = work.saturating_add(command_work);
        if work > MAX_DRAW_WORK_UNITS {
            return Err(MediaError::Limit("draw work budget exceeded".into()));
        }
        match command {
            DrawCommand::Rect {
                x,
                y,
                width,
                height,
                ..
            }
            | DrawCommand::Image {
                x,
                y,
                width,
                height,
                ..
            } => {
                validate_coordinate(*x, frame.logical_width)?;
                validate_coordinate(*y, frame.logical_height)?;
                if u64::from(*width) > u64::from(frame.logical_width) * 8
                    || u64::from(*height) > u64::from(frame.logical_height) * 8
                {
                    return Err(MediaError::Limit("draw extent is too large".into()));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_coordinate(value: i32, logical: u32) -> Result<()> {
    let bound = i64::from(logical) * 8;
    if i64::from(value).abs() > bound {
        return Err(MediaError::Limit(
            "draw coordinate is too far outside the canvas".into(),
        ));
    }
    Ok(())
}

fn validate_asset_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_MEDIA_ASSET_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
    {
        return Err(MediaError::Asset(
            "media asset path is not normalized".into(),
        ));
    }
    Ok(())
}

fn clear(rgba: &mut [u8], color: Color) {
    for pixel in rgba.chunks_exact_mut(4) {
        pixel.copy_from_slice(&[color.r, color.g, color.b, color.a]);
    }
}

#[allow(clippy::too_many_arguments)]
fn fill_rect(
    rgba: &mut [u8],
    canvas_width: u32,
    canvas_height: u32,
    scale: Scale,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    color: Color,
) {
    let x = scale.x(x);
    let y = scale.y(y);
    let width = scale.w(width);
    let height = scale.h(height);
    let left = x.max(0) as u32;
    let top = y.max(0) as u32;
    let right = i64::from(x)
        .saturating_add(i64::from(width))
        .clamp(0, i64::from(canvas_width)) as u32;
    let bottom = i64::from(y)
        .saturating_add(i64::from(height))
        .clamp(0, i64::from(canvas_height)) as u32;
    for py in top..bottom {
        for px in left..right {
            blend(rgba, canvas_width, px, py, color);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_line(
    rgba: &mut [u8],
    canvas_width: u32,
    canvas_height: u32,
    scale: Scale,
    from: (i32, i32),
    to: (i32, i32),
    width: u16,
    color: Color,
) {
    let (mut x0, mut y0) = (scale.x(from.0), scale.y(from.1));
    let (x1, y1) = (scale.x(to.0), scale.y(to.1));
    let dx = i64::from(x1).abs_diff(i64::from(x0)) as i64;
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(i64::from(y1).abs_diff(i64::from(y0)) as i64);
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    let radius = i32::from(width.min(64)) / 2;
    loop {
        for oy in -radius..=radius {
            for ox in -radius..=radius {
                let px = x0.saturating_add(ox);
                let py = y0.saturating_add(oy);
                if px >= 0 && py >= 0 && (px as u32) < canvas_width && (py as u32) < canvas_height {
                    blend(rgba, canvas_width, px as u32, py as u32, color);
                }
            }
        }
        if x0 == x1 && y0 == y1 {
            break;
        }
        let doubled = error.saturating_mul(2);
        if doubled >= dy {
            error += dy;
            x0 += sx;
        }
        if doubled <= dx {
            error += dx;
            y0 += sy;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn blit(
    rgba: &mut [u8],
    canvas_width: u32,
    canvas_height: u32,
    scale: Scale,
    source: &[u8],
    source_width: u32,
    source_height: u32,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
) -> Result<()> {
    let x = scale.x(x);
    let y = scale.y(y);
    let width = scale.w(width);
    let height = scale.h(height);
    if width == 0 || height == 0 {
        return Ok(());
    }
    let left = i64::from(x).clamp(0, i64::from(canvas_width));
    let top = i64::from(y).clamp(0, i64::from(canvas_height));
    let right = i64::from(x)
        .saturating_add(i64::from(width))
        .clamp(0, i64::from(canvas_width));
    let bottom = i64::from(y)
        .saturating_add(i64::from(height))
        .clamp(0, i64::from(canvas_height));
    for py in top..bottom {
        for px in left..right {
            let dx = u64::try_from(px - i64::from(x))
                .map_err(|_| MediaError::Invalid("image x offset became negative".into()))?;
            let dy = u64::try_from(py - i64::from(y))
                .map_err(|_| MediaError::Invalid("image y offset became negative".into()))?;
            let sx = dx * u64::from(source_width) / u64::from(width);
            let sy = dy * u64::from(source_height) / u64::from(height);
            let index = usize::try_from((sy * u64::from(source_width) + sx) * 4)
                .map_err(|_| MediaError::Limit("image index is not addressable".into()))?;
            let pixel = source
                .get(index..index + 4)
                .ok_or_else(|| MediaError::Asset("image pixel is outside its payload".into()))?;
            blend(
                rgba,
                canvas_width,
                u32::try_from(px).map_err(|_| {
                    MediaError::Limit("image x coordinate is not addressable".into())
                })?,
                u32::try_from(py).map_err(|_| {
                    MediaError::Limit("image y coordinate is not addressable".into())
                })?,
                Color {
                    r: pixel[0],
                    g: pixel[1],
                    b: pixel[2],
                    a: pixel[3],
                },
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn draw_text(
    rgba: &mut [u8],
    canvas_width: u32,
    canvas_height: u32,
    scale: Scale,
    text: &str,
    font: Option<&[u8]>,
    x: i32,
    y: i32,
    size: u16,
    color: Color,
) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    let parsed = font.map(parse_font).transpose()?;
    let glyph_width = parsed.as_ref().map_or(5, |value| value.0);
    let glyph_height = parsed.as_ref().map_or(7, |value| value.1);
    let pixel_scale = u32::from(size);
    let mut cursor = x;
    for character in text.chars() {
        if character == '\n' {
            continue;
        }
        let bits = parsed
            .as_ref()
            .and_then(|font| custom_glyph(font, character))
            .unwrap_or_else(|| builtin_glyph(character));
        for row in 0..glyph_height {
            for column in 0..glyph_width {
                let offset = usize::from(row) * usize::from(glyph_width) + usize::from(column);
                if bits.get(offset).is_some_and(|bit| *bit) {
                    fill_rect(
                        rgba,
                        canvas_width,
                        canvas_height,
                        scale,
                        cursor.saturating_add(i32::from(column) * i32::from(size)),
                        y.saturating_add(i32::from(row) * i32::from(size)),
                        pixel_scale,
                        pixel_scale,
                        color,
                    );
                }
            }
        }
        cursor = cursor.saturating_add((i32::from(glyph_width) + 1) * i32::from(size));
    }
    Ok(())
}

type ParsedFont = (u8, u8, Vec<bool>);

fn parse_font(bytes: &[u8]) -> Result<ParsedFont> {
    if bytes.len() < 6 || &bytes[..4] != b"CFNT" {
        return Err(MediaError::Asset(
            "font asset does not have a CFNT header".into(),
        ));
    }
    let width = bytes[4];
    let height = bytes[5];
    if width == 0 || height == 0 || width > 16 || height > 32 {
        return Err(MediaError::Asset("font dimensions are invalid".into()));
    }
    let bits = 95usize
        .checked_mul(usize::from(width))
        .and_then(|value| value.checked_mul(usize::from(height)))
        .ok_or_else(|| MediaError::Asset("font dimensions overflow".into()))?;
    let packed = bits.div_ceil(8);
    if bytes.len() != 6 + packed {
        return Err(MediaError::Asset("font payload length is invalid".into()));
    }
    let decoded = (0..bits)
        .map(|index| bytes[6 + index / 8] & (1 << (7 - index % 8)) != 0)
        .collect();
    Ok((width, height, decoded))
}

fn custom_glyph(font: &ParsedFont, character: char) -> Option<&[bool]> {
    let code = u32::from(character);
    if !(32..=126).contains(&code) {
        return None;
    }
    let glyph_bits = usize::from(font.0) * usize::from(font.1);
    let start = usize::try_from(code - 32).ok()?.checked_mul(glyph_bits)?;
    font.2.get(start..start + glyph_bits)
}

fn builtin_glyph(character: char) -> &'static [bool] {
    const EMPTY: [bool; 35] = [false; 35];
    const BLOCK: [bool; 35] = [true; 35];
    if character == ' ' { &EMPTY } else { &BLOCK }
}

fn blend(rgba: &mut [u8], width: u32, x: u32, y: u32, source: Color) {
    let Some(index) = (u64::from(y) * u64::from(width) + u64::from(x))
        .checked_mul(4)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return;
    };
    let Some(pixel) = rgba.get_mut(index..index + 4) else {
        return;
    };
    let alpha = u32::from(source.a);
    let inverse = 255 - alpha;
    pixel[0] = ((u32::from(source.r) * alpha + u32::from(pixel[0]) * inverse + 127) / 255) as u8;
    pixel[1] = ((u32::from(source.g) * alpha + u32::from(pixel[1]) * inverse + 127) / 255) as u8;
    pixel[2] = ((u32::from(source.b) * alpha + u32::from(pixel[2]) * inverse + 127) / 255) as u8;
    pixel[3] = (alpha + u32::from(pixel[3]) * inverse / 255).min(255) as u8;
}

fn checked_rgba_len(width: u32, height: u32) -> Result<usize> {
    usize::try_from(width)
        .ok()
        .and_then(|width| {
            usize::try_from(height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| MediaError::Limit("image dimensions overflow".into()))
}

fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut output), width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::Fast);
        let mut writer = encoder
            .write_header()
            .map_err(|error| MediaError::Encoding(error.to_string()))?;
        writer
            .write_image_data(rgba)
            .map_err(|error| MediaError::Encoding(error.to_string()))?;
    }
    Ok(output)
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendering_is_deterministic() {
        let mut display = HeadlessDisplay::new(GraphicsLimits::default());
        let window = display
            .open(WindowConfig {
                title: "test".into(),
                width: 32,
                height: 24,
            })
            .unwrap();
        let frame = serde_json::to_vec(&FrameDocument {
            logical_width: 320,
            logical_height: 240,
            simulation_tick: 0,
            commands: vec![
                DrawCommand::Clear {
                    color: Color {
                        r: 1,
                        g: 2,
                        b: 3,
                        a: 255,
                    },
                },
                DrawCommand::Rect {
                    x: 10,
                    y: 10,
                    width: 40,
                    height: 20,
                    color: Color {
                        r: 200,
                        g: 40,
                        b: 80,
                        a: 180,
                    },
                },
            ],
        })
        .unwrap();
        let first = display.present(window, &frame, |_| None).unwrap();
        let second = display.present(window, &frame, |_| None).unwrap();
        assert_eq!(first.rgba_sha256, second.rgba_sha256);
        assert_eq!(first.png_sha256, second.png_sha256);
    }

    #[test]
    fn invalid_image_length_is_rejected() {
        let mut display = HeadlessDisplay::new(GraphicsLimits::default());
        let window = display
            .open(WindowConfig {
                title: String::new(),
                width: 8,
                height: 8,
            })
            .unwrap();
        let frame = serde_json::to_vec(&FrameDocument {
            logical_width: 8,
            logical_height: 8,
            simulation_tick: 0,
            commands: vec![DrawCommand::Image {
                asset: "bad".into(),
                source_width: u32::MAX,
                source_height: u32::MAX,
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }],
        })
        .unwrap();
        assert!(display.present(window, &frame, |_| Some(&[])).is_err());
    }

    #[test]
    fn simulation_time_cannot_go_backwards() {
        let mut display = HeadlessDisplay::new(GraphicsLimits::default());
        let window = display
            .open(WindowConfig {
                title: String::new(),
                width: 8,
                height: 8,
            })
            .unwrap();
        let frame = |tick| {
            serde_json::to_vec(&FrameDocument {
                logical_width: 8,
                logical_height: 8,
                simulation_tick: tick,
                commands: Vec::new(),
            })
            .unwrap()
        };
        display.present(window, &frame(2), |_| None).unwrap();
        assert!(display.present(window, &frame(1), |_| None).is_err());
    }

    #[test]
    fn hostile_geometry_is_rejected_before_rasterization() {
        let mut display = HeadlessDisplay::new(GraphicsLimits::default());
        let window = display
            .open(WindowConfig {
                title: String::new(),
                width: 64,
                height: 64,
            })
            .unwrap();
        let line = serde_json::to_vec(&FrameDocument {
            logical_width: 64,
            logical_height: 64,
            simulation_tick: 0,
            commands: vec![DrawCommand::Line {
                x1: i32::MIN,
                y1: 0,
                x2: i32::MAX,
                y2: 0,
                width: 64,
                color: Color {
                    r: 0,
                    g: 0,
                    b: 0,
                    a: 255,
                },
            }],
        })
        .unwrap();
        assert!(display.present(window, &line, |_| None).is_err());

        let image = serde_json::to_vec(&FrameDocument {
            logical_width: 64,
            logical_height: 64,
            simulation_tick: 0,
            commands: vec![DrawCommand::Image {
                asset: "empty".into(),
                source_width: 0,
                source_height: 0,
                x: 0,
                y: 0,
                width: u32::MAX,
                height: u32::MAX,
            }],
        })
        .unwrap();
        assert!(display.present(window, &image, |_| Some(&[])).is_err());
    }

    #[test]
    fn exhausted_capture_quota_rejects_before_parsing_or_rendering() {
        let mut display = HeadlessDisplay::new(GraphicsLimits::default());
        let window = display
            .open(WindowConfig {
                title: String::new(),
                width: 1,
                height: 1,
            })
            .unwrap();
        display.captured_bytes = MAX_CAPTURED_GRAPHICS_BYTES;
        assert!(display.present(window, b"not json", |_| None).is_err());
    }

    #[test]
    fn media_assets_require_normalized_paths() {
        assert!(validate_asset_path("images/icon.rgba").is_ok());
        assert!(validate_asset_path("../icon.rgba").is_err());
        assert!(validate_asset_path("C:/icon.rgba").is_err());
        assert!(validate_asset_path("images\\icon.rgba").is_err());
    }
}
