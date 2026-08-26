// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Repository-specific source-package inventory policy.

use crate::package_content::PackageSpec;

pub(crate) const PACKAGE_SPECS: &[PackageSpec] = &[PackageSpec {
    name: "yaml-sigil-traits",
    inventory_path: "xtask/package-contents/yaml-sigil-traits.txt",
    inventory: include_str!("../package-contents/yaml-sigil-traits.txt"),
}];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_scope_and_order_are_explicit() {
        assert_eq!(
            PACKAGE_SPECS
                .iter()
                .map(|package| package.name)
                .collect::<Vec<_>>(),
            ["yaml-sigil-traits"]
        );
    }
}
