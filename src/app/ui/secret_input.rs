//! Delegate every widget operation unchanged except password clipboard writes.
//! Iced's text input otherwise bypasses the managed copy path when revealed.
use iced::advanced::{
    Clipboard, Layout, Shell, Widget, clipboard, layout, mouse, overlay, renderer, widget,
};
use iced::{Element, Event, Length, Rectangle, Renderer, Size, Theme, Vector};
use iced::{keyboard, widget::text_input};
use unicode_segmentation::UnicodeSegmentation;
use zeroize::Zeroizing;

use super::{EditorCut, Message};

pub(super) fn managed_password_input<'a>(
    content: iced::widget::TextInput<'a, Message>,
    generation: u64,
    original: &'a str,
    revealed: bool,
) -> Element<'a, Message> {
    Element::new(ManagedInput {
        content: content.into(),
        generation,
        original,
        revealed,
        current: std::cell::RefCell::new(None),
        modifiers: keyboard::Modifiers::empty(),
    })
}

struct ManagedInput<'a> {
    content: Element<'a, Message>,
    generation: u64,
    original: &'a str,
    revealed: bool,
    current: std::cell::RefCell<Option<Zeroizing<String>>>,
    modifiers: keyboard::Modifiers,
}

struct RoutedClipboard<'a> {
    inner: &'a mut dyn Clipboard,
    writes: Vec<Zeroizing<String>>,
}

impl Clipboard for RoutedClipboard<'_> {
    fn read(&self, kind: clipboard::Kind) -> Option<String> {
        self.inner.read(kind)
    }
    fn write(&mut self, _kind: clipboard::Kind, contents: String) {
        self.writes.push(Zeroizing::new(contents));
    }
}

impl Widget<Message, Theme, Renderer> for ManagedInput<'_> {
    fn tag(&self) -> widget::tree::Tag {
        self.content.as_widget().tag()
    }
    fn state(&self) -> widget::tree::State {
        self.content.as_widget().state()
    }
    fn children(&self) -> Vec<widget::Tree> {
        self.content.as_widget().children()
    }
    fn diff(&self, tree: &mut widget::Tree) {
        self.content.as_widget().diff(tree);
    }
    fn size(&self) -> Size<Length> {
        self.content.as_widget().size()
    }
    fn size_hint(&self) -> Size<Length> {
        self.content.as_widget().size_hint()
    }
    fn layout(
        &mut self,
        tree: &mut widget::Tree,
        renderer: &Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        self.content.as_widget_mut().layout(tree, renderer, limits)
    }
    fn draw(
        &self,
        tree: &widget::Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        style: &renderer::Style,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        self.content
            .as_widget()
            .draw(tree, renderer, theme, style, layout, cursor, viewport);
    }
    fn operate(
        &mut self,
        tree: &mut widget::Tree,
        layout: Layout<'_>,
        renderer: &Renderer,
        operation: &mut dyn widget::Operation,
    ) {
        self.content
            .as_widget_mut()
            .operate(tree, layout, renderer, operation);
    }
    fn update(
        &mut self,
        tree: &mut widget::Tree,
        event: &Event,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        renderer: &Renderer,
        clipboard: &mut dyn Clipboard,
        shell: &mut Shell<'_, Message>,
        viewport: &Rectangle,
    ) {
        if let Event::Keyboard(keyboard::Event::ModifiersChanged(modifiers)) = event {
            self.modifiers = *modifiers;
        }
        if matches!(event, Event::Window(iced::window::Event::Unfocused)) {
            self.modifiers = keyboard::Modifiers::empty();
        }
        let cut = matches!(event,
            Event::Keyboard(keyboard::Event::KeyPressed { key, physical_key, modifiers, .. })
            if key.to_latin(*physical_key) == Some('x') && (modifiers.command() || self.modifiers.command())
        );
        if cut {
            type InputState =
                text_input::State<<Renderer as iced::advanced::text::Renderer>::Paragraph>;
            let state = tree.state.downcast_mut::<InputState>();
            if state.is_focused() {
                shell.capture_event();
                if self.revealed {
                    let current = self.current.borrow();
                    let current = current
                        .as_ref()
                        .map(|value| value.as_str())
                        .unwrap_or(self.original);
                    // Use the same mature grapheme segmentation as Iced. Only
                    // offsets and bullet glyphs enter the temporary Value.
                    let boundaries: Vec<usize> = current
                        .grapheme_indices(true)
                        .map(|(offset, _)| offset)
                        .chain([current.len()])
                        .collect();
                    let mask = text_input::Value::new(&"•".repeat(boundaries.len() - 1));
                    if let Some((start, end)) = state.cursor().selection(&mask) {
                        let selected =
                            Zeroizing::new(current[boundaries[start]..boundaries[end]].to_owned());
                        let mut replacement = Zeroizing::new(String::with_capacity(current.len()));
                        replacement.push_str(&current[..boundaries[start]]);
                        replacement.push_str(&current[boundaries[end]..]);
                        // Do not let the child mutate its value before native
                        // success. Continuing to type cancels the deletion and
                        // preserves the original selection instead of losing it.
                        state.move_cursor_to(end);
                        shell.publish(Message::CopyEditorPasswordSelection(
                            self.generation,
                            selected,
                            Some(EditorCut {
                                original: Zeroizing::new(current.to_owned()),
                                replacement,
                            }),
                        ));
                    }
                }
                // Ctrl+X without a selection is explicitly a no-op.
                return;
            }
        }
        let mut routed = RoutedClipboard {
            inner: clipboard,
            writes: Vec::new(),
        };
        let mut messages = Vec::new();
        let mut local_shell = Shell::new(&mut messages);
        self.content.as_widget_mut().update(
            tree,
            event,
            layout,
            cursor,
            renderer,
            &mut routed,
            &mut local_shell,
            viewport,
        );
        shell.merge(local_shell, |message| {
            if let Message::EditorPasswordChanged(value) = &message {
                // Track edits within one native event batch, before App updates.
                *self.current.borrow_mut() = Some(Zeroizing::new(value.clone()));
            }
            message
        });
        for value in routed.writes {
            shell.publish(Message::CopyEditorPasswordSelection(
                self.generation,
                value,
                None,
            ));
        }
    }

    fn mouse_interaction(
        &self,
        tree: &widget::Tree,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
        renderer: &Renderer,
    ) -> mouse::Interaction {
        self.content
            .as_widget()
            .mouse_interaction(tree, layout, cursor, viewport, renderer)
    }
    fn overlay<'a>(
        &'a mut self,
        tree: &'a mut widget::Tree,
        layout: Layout<'a>,
        renderer: &Renderer,
        viewport: &Rectangle,
        translation: Vector,
    ) -> Option<overlay::Element<'a, Message, Theme, Renderer>> {
        self.content
            .as_widget_mut()
            .overlay(tree, layout, renderer, viewport, translation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct FakeClipboard {
        writes: usize,
    }
    impl Clipboard for FakeClipboard {
        fn read(&self, _kind: clipboard::Kind) -> Option<String> {
            Some("synthetic-paste".into())
        }
        fn write(&mut self, _kind: clipboard::Kind, _contents: String) {
            self.writes += 1;
        }
    }
    #[test]
    fn password_input_never_writes_directly_to_system_clipboard() {
        let mut clipboard = FakeClipboard::default();
        let mut routed = RoutedClipboard {
            inner: &mut clipboard,
            writes: Vec::new(),
        };
        assert_eq!(
            routed.read(clipboard::Kind::Standard).as_deref(),
            Some("synthetic-paste")
        );
        routed.write(clipboard::Kind::Standard, "synthetic-selection".into());
        assert_eq!(routed.writes[0].as_str(), "synthetic-selection");
        drop(routed);
        assert_eq!(clipboard.writes, 0);
    }
}
