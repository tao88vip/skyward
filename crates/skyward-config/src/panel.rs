/// Names under `/proc/device-tree/soc` that may hold the panel the display
/// driver booted with. Some bootloaders report the driver's internal name
/// (`dsi_..._display`) while the device tree uses the panel node's name
/// (`qcom,mdss_dsi_...`).
pub fn node_candidates(name: &str) -> Vec<String> {
    let mut names = Vec::with_capacity(3);
    let mut add = |candidate: &str| {
        if !names.iter().any(|existing| existing == candidate) {
            names.push(candidate.to_owned());
        }
    };

    add(name);
    if let Some(base) = name.strip_suffix("_display") {
        add(base);
        if let Some(rest) = base.strip_prefix("dsi_") {
            add(&format!("qcom,mdss_dsi_{rest}"));
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::node_candidates;

    #[test]
    fn maps_a_driver_name_to_the_crux_panel_node() {
        assert_eq!(
            node_candidates("dsi_samsung_fhd_ea8076_f1s_cmd_display"),
            [
                "dsi_samsung_fhd_ea8076_f1s_cmd_display",
                "dsi_samsung_fhd_ea8076_f1s_cmd",
                "qcom,mdss_dsi_samsung_fhd_ea8076_f1s_cmd",
            ]
        );
    }

    #[test]
    fn keeps_an_existing_device_tree_name_first() {
        assert_eq!(
            node_candidates("qcom,mdss_dsi_m1_42_02_0a_dsc_cmd"),
            ["qcom,mdss_dsi_m1_42_02_0a_dsc_cmd"]
        );
    }

    #[test]
    fn strips_display_without_inventing_a_qualcomm_prefix() {
        assert_eq!(
            node_candidates("other_panel_display"),
            ["other_panel_display", "other_panel"]
        );
    }
}
