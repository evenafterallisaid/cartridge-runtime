use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::{MediaError, Result};

pub const MAX_INPUT_EVENTS: usize = 4096;
pub const MAX_TEXT_INPUT_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InputEvent {
    Key {
        code: u16,
        pressed: bool,
        repeat: bool,
    },
    PointerMove {
        x: i32,
        y: i32,
    },
    PointerButton {
        button: u8,
        pressed: bool,
    },
    PointerWheel {
        x: i16,
        y: i16,
    },
    ControllerAxis {
        controller: u8,
        axis: u8,
        value: i16,
    },
    ControllerButton {
        controller: u8,
        button: u8,
        pressed: bool,
    },
    Text {
        value: String,
    },
    CloseRequested,
}

#[derive(Clone, Debug)]
pub struct InputQueue {
    events: VecDeque<InputEvent>,
    capacity: usize,
}

impl InputQueue {
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_INPUT_EVENTS {
            return Err(MediaError::Limit(format!(
                "input capacity must be between 1 and {MAX_INPUT_EVENTS}"
            )));
        }
        Ok(Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
        })
    }

    pub fn push(&mut self, event: InputEvent) -> Result<()> {
        validate_event(&event)?;
        if self.events.len() == self.capacity {
            return Err(MediaError::Limit("input queue is full".into()));
        }
        self.events.push_back(event);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<InputEvent> {
        self.events.pop_front()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl InputEvent {
    pub fn validate(self) -> Result<Self> {
        validate_event(&self)?;
        Ok(self)
    }
}

fn validate_event(event: &InputEvent) -> Result<()> {
    if let InputEvent::Text { value } = event {
        if value.len() > MAX_TEXT_INPUT_BYTES {
            return Err(MediaError::Limit(format!(
                "text input exceeds {MAX_TEXT_INPUT_BYTES} bytes"
            )));
        }
        if value.chars().any(|character| character == '\0') {
            return Err(MediaError::Invalid(
                "text input contains a null character".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_is_bounded() {
        let mut queue = InputQueue::new(1).unwrap();
        queue.push(InputEvent::CloseRequested).unwrap();
        assert!(queue.push(InputEvent::CloseRequested).is_err());
        assert_eq!(queue.pop(), Some(InputEvent::CloseRequested));
    }
}
