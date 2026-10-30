// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use std::{collections::HashSet, sync::Arc};

// Bucket identity is independent of the matching descriptor and its position.
pub type Key = (Arc<[Action]>, Vec<String>);

pub fn default_budget_name() -> String {
    "default".into()
}
pub fn default_capacity() -> usize {
    10000
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub actions: Arc<[Action]>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    FilterState {
        key: String,
        descriptor_key: String,
    },
    GenericKey {
        descriptor_key: String,
        descriptor_value: String,
    },
}

impl Action {
    pub fn key(&self) -> &str {
        match self {
            Self::FilterState { descriptor_key, .. } | Self::GenericKey { descriptor_key, .. } => {
                descriptor_key
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub key: String,
    #[serde(default)]
    pub value: String,
}

pub trait MatchDescriptor {
    fn entries(&self) -> &[Entry];
    fn dynamic(&self) -> bool {
        self.entries().iter().any(|e| e.value.is_empty())
    }
}

pub fn validate_groups<D: MatchDescriptor>(
    rules: &[RateLimit],
    descriptors: &[D],
) -> Result<(), String> {
    if rules.is_empty() || descriptors.is_empty() {
        return Err("rate_limits and descriptors must not be empty".into());
    }
    for rule in rules {
        let mut keys = HashSet::new();
        if rule.actions.is_empty() {
            return Err("actions must not be empty".into());
        }
        for action in rule.actions.iter() {
            if action.key().is_empty() || !keys.insert(action.key()) {
                return Err("descriptor keys must be nonempty and unique within actions".into());
            }
            match action {
                Action::FilterState { key, .. } if key.is_empty() => {
                    return Err("filter state key must not be empty".into());
                }
                Action::GenericKey {
                    descriptor_value, ..
                } if descriptor_value.is_empty() => {
                    return Err("generic_key value must not be empty".into());
                }
                _ => {}
            }
        }
    }
    for (index, descriptor) in descriptors.iter().enumerate() {
        if !rules.iter().any(|r| {
            r.actions
                .iter()
                .map(Action::key)
                .eq(descriptor.entries().iter().map(|e| e.key.as_str()))
        }) {
            return Err("descriptor entries must match an action group's keys in order".into());
        }
        if descriptors[..index]
            .iter()
            .any(|d| d.entries() == descriptor.entries())
        {
            return Err("duplicate descriptor entries".into());
        }
    }
    Ok(())
}

pub fn same_layout<D: MatchDescriptor>(
    rules: &[RateLimit],
    descriptors: &[D],
    other_rules: &[RateLimit],
    other: &[D],
) -> bool {
    rules == other_rules
        && descriptors.len() == other.len()
        && descriptors
            .iter()
            .zip(other)
            .all(|(a, b)| a.entries() == b.entries())
}

pub fn resolve<D: MatchDescriptor>(
    rules: &[RateLimit],
    descriptors: &[D],
    mut get: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<Key>, ()> {
    let mut matched = Vec::new();
    for rule in rules {
        let values: Vec<String> = rule
            .actions
            .iter()
            .map(|a| match a {
                Action::FilterState { key, .. } => get(key).filter(|s| !s.is_empty()).ok_or(()),
                Action::GenericKey {
                    descriptor_value, ..
                } => Ok(descriptor_value.clone()),
            })
            .collect::<Result<_, _>>()?;
        let key = (rule.actions.clone(), values);
        if matching_descriptor(rules, descriptors, &key).is_some() && !matched.contains(&key) {
            matched.push(key);
        }
    }
    Ok(matched)
}

// Full exact matches win; wildcard priority remains the configured order.
pub fn matching_descriptor<'a, D: MatchDescriptor>(
    rules: &[RateLimit],
    descriptors: &'a [D],
    key: &Key,
) -> Option<&'a D> {
    if !rules.iter().any(|rule| rule.actions == key.0) {
        return None;
    }
    let matches = |d: &&D| {
        key.0.len() == d.entries().len()
            && key
                .0
                .iter()
                .zip(&key.1)
                .zip(d.entries())
                .all(|((action, value), entry)| {
                    action.key() == entry.key && (entry.value.is_empty() || entry.value == *value)
                })
    };
    descriptors
        .iter()
        .find(|d| !d.dynamic() && matches(d))
        .or_else(|| descriptors.iter().find(matches))
}
