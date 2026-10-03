//! Snapshot-bound, metadata-only indexes prepared on the operation worker.
//! Passwords, notes and decrypted secret buffers are never stored here.
use super::NavFilter;
use crate::{domain::EntryRecord, operations::SessionBinding, storage::VaultSession};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct ViewIndex {
    binding: SessionBinding,
    by_id: HashMap<Uuid, usize>,
    all: Vec<usize>,
    favorites: Vec<usize>,
    deleted: Vec<usize>,
    categories: BTreeMap<String, Vec<usize>>,
    searchable: Vec<SearchMetadata>,
}

#[derive(Debug)]
struct SearchMetadata {
    name: String,
    website: String,
    username: String,
}

impl ViewIndex {
    pub(crate) fn build(session: &VaultSession) -> Self {
        let mut index = Self {
            binding: session.operation_binding(),
            by_id: HashMap::with_capacity(session.entries().len()),
            all: Vec::new(),
            favorites: Vec::new(),
            deleted: Vec::new(),
            categories: BTreeMap::new(),
            searchable: Vec::with_capacity(session.entries().len()),
        };
        for (position, entry) in session.entries().iter().enumerate() {
            index.by_id.entry(entry.id).or_insert(position);
            index.searchable.push(SearchMetadata {
                name: entry.name.to_lowercase(),
                website: entry.website.to_lowercase(),
                username: entry.username.to_lowercase(),
            });
            if entry.is_deleted() {
                index.deleted.push(position);
            } else {
                index.all.push(position);
                if entry.favorite {
                    index.favorites.push(position);
                }
                index
                    .categories
                    .entry(entry.category.clone())
                    .or_default()
                    .push(position);
            }
        }
        index
    }
    pub(crate) fn active_count(&self) -> usize {
        self.all.len()
    }
    pub(crate) fn favorite_count(&self) -> usize {
        self.favorites.len()
    }
    pub(crate) fn deleted_count(&self) -> usize {
        self.deleted.len()
    }
    pub(crate) fn category_count(&self, category: &str) -> usize {
        self.categories.get(category).map_or(0, Vec::len)
    }
    pub(in crate::app) fn positions(&self, nav: &NavFilter) -> &[usize] {
        match nav {
            NavFilter::All => &self.all,
            NavFilter::Favorites => &self.favorites,
            NavFilter::RecycleBin => &self.deleted,
            NavFilter::Category(name) => self.categories.get(name).map_or(&[], Vec::as_slice),
        }
    }
    pub(in crate::app) fn filter(&self, nav: &NavFilter, query: &str) -> Vec<usize> {
        let query = query.to_lowercase();
        self.positions(nav)
            .iter()
            .copied()
            .filter(|position| {
                let metadata = &self.searchable[*position];
                query.is_empty()
                    || metadata.name.contains(&query)
                    || metadata.website.contains(&query)
                    || metadata.username.contains(&query)
            })
            .collect()
    }
    pub(crate) fn position(&self, session: &VaultSession, id: Uuid) -> Option<usize> {
        if self.binding != session.operation_binding() {
            return None;
        }
        let position = *self.by_id.get(&id)?;
        session
            .entries()
            .get(position)
            .is_some_and(|entry| entry.id == id)
            .then_some(position)
    }
    pub(crate) fn entry<'a>(&self, session: &'a VaultSession, id: Uuid) -> Option<&'a EntryRecord> {
        session.entries().get(self.position(session, id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_metadata_index_preserves_reference_filter_order_and_counts() {
        let (_directory, mut app) = crate::app::tests::fixture(65);
        let session = app.session.as_mut().unwrap();
        for (position, entry) in session.body_mut().entries.iter_mut().enumerate() {
            entry.category = format!("category-{}", position % 3);
            entry.favorite = position % 4 == 0;
            if position % 7 == 0 {
                entry.deleted_at_unix = Some(123);
            }
            if position % 5 == 0 {
                entry.name = "Mixed CASE 中文😀".into();
            }
        }
        let session = app.session.as_ref().unwrap();
        let index = ViewIndex::build(session);
        for nav in [
            NavFilter::All,
            NavFilter::Favorites,
            NavFilter::RecycleBin,
            NavFilter::Category("category-1".into()),
            NavFilter::Category("missing".into()),
        ] {
            app.nav = nav.clone();
            for query in ["", "mixed", "CASE", "中文😀", "synthetic-user-6", "missing"] {
                let expected: Vec<_> = app
                    .session
                    .as_ref()
                    .unwrap()
                    .entries()
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| app.entry_visible(entry, &query.to_lowercase()))
                    .map(|(position, _)| position)
                    .collect();
                assert_eq!(index.filter(&nav, query), expected);
            }
        }
        let session = app.session.as_ref().unwrap();
        assert_eq!(index.active_count(), session.active_entries().count());
        assert_eq!(
            index.favorite_count(),
            session
                .active_entries()
                .filter(|entry| entry.favorite)
                .count()
        );
        assert_eq!(
            index.deleted_count(),
            session
                .entries()
                .iter()
                .filter(|entry| entry.is_deleted())
                .count()
        );
        assert_eq!(
            index.category_count("category-1"),
            session
                .active_entries()
                .filter(|entry| entry.category == "category-1")
                .count()
        );
        for entry in session.entries() {
            assert_eq!(index.entry(session, entry.id), Some(entry));
        }
    }
    #[test]
    fn prepared_metadata_lookup_rejects_another_session_at_same_path() {
        let (_directory, app) = crate::app::tests::fixture(3);
        let session = app.session.as_ref().unwrap();
        let index = ViewIndex::build(session);
        let reopened = VaultSession::open(session.path(), "gui-synthetic-master-only").unwrap();
        assert!(index.entry(&reopened, session.entries()[0].id).is_none());
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    #[test]
    fn prepared_metadata_lookup_keeps_first_duplicate_id_like_session_entry() {
        let (_directory, mut app) = crate::app::tests::fixture(2);
        let session = app.session.as_mut().unwrap();
        let mut duplicate = session.entries()[0].clone();
        let id = duplicate.id;
        duplicate.name = "synthetic later duplicate metadata".into();
        session.body_mut().entries.push(duplicate);
        session.save().unwrap();
        let index = ViewIndex::build(session);
        assert_eq!(
            index.entry(session, id),
            session.entry(id),
            "accepted duplicate-ID metadata must preserve existing first-entry lookup behavior"
        );
    }
}
