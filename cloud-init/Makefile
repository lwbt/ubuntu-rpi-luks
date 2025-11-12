# cspell:ignore ireduce

SRC_DIR := files
LIB_DIR := lib
OUT_DIR := updated-cloud-init

.PHONY: all
all: $(OUT_DIR)/rpi4_user-data_server.yaml $(OUT_DIR)/rpi4_user-data_desktop.yaml
	tree $(OUT_DIR)

.PHONY: clean
clean:
	@rm -v \
	test.yaml \
	$(OUT_DIR)/rpi4_user-data_server.yaml \
	$(OUT_DIR)/rpi4_user-data_desktop.yaml || true
	@rmdir -v $(OUT_DIR)

# NOTE: Using this directive to refresh a large portion of the write_files
#       section is not elegant, but good enough for now.
.PHONY: $(LIB_DIR)/user_data_write_files_includes.yaml refresh-write-files-includes
$(LIB_DIR)/user_data_write_files_includes.yaml:
	@mkdir -pv $(dir $@)
	@# This doesn't work yet. It worked in the example?
	@#@dest=/etc/skel/dconf_load.ini
	@printf -- '---\nautoinstall:\n  user-data:\n    write_files:\n' > $@
	@# 52unattended-upgrades-local.apt.conf
	@printf '      # Configure override for unattended-upgrades.\n' >> $@
	@printf -- '      - path: "%s"\n        content: |\n' \
	  "/etc/apt/apt.conf.d/52unattended-upgrades-local.conf" >> $@
	@sed '/./s/^/          /' "$(SRC_DIR)/52unattended-upgrades-local.apt.conf" >> $@
	@# logind.conf
	@printf '      # Suspend System to RAM when pressing the power button.\n' >> $@
	@printf '      # Without this, the setting in Gnome does not work.\n' >> $@
	@printf '      # cspell:ignore logind\n' >> $@
	@printf -- '      - path: "%s"\n        append: true\n        content: |\n' \
	  "/etc/systemd/logind.conf" >> $@
	@sed '/./s/^/          /' "$(SRC_DIR)/logind.conf" >> $@
	@# bashrc.sh
	@printf '      # Add ~/.local/bin to PATH, required at least for pipx.\n' >> $@
	@printf -- '      - path: "%s"\n        append: true\n        content: |\n' \
	  "/etc/skel/.bashrc" >> $@
	@sed '/./s/^/          /' "$(SRC_DIR)/bashrc.sh" >> $@
	@# post_install_setup.sh
	@printf '      # Post-Installation Setup for users part 1/2.\n' >> $@
	@printf -- '      - path: "%s"\n        permissions: "0755"\n        content: |\n' \
	  "/etc/skel/post_install_setup.sh" >> $@
	@# This indents the content from the original file and appends it to the
	@# end for the destination file.
	@sed '/./s/^/          /' "$(SRC_DIR)/post_install_setup.sh" >> $@
	@# dconf_load.ini
	@printf '      # Post-Installation Setup for users part 2/2.\n' >> $@
	@printf '      # cspell:ignore weekdate luxon\n' >> $@
	@printf -- '      - path: "%s"\n        content: |\n' \
	  "/etc/skel/dconf_load.ini" >> $@
	@sed '/./s/^/          /' "$(SRC_DIR)/dconf_load.ini" >> $@
	@# ubuntu-default-dynamic.xml
	@printf '      # Dynamic wallpaper part 1/2.\n' >> $@
	@printf '      # cspell:ignore starttime maoschanz\n' >> $@
	@printf -- '      - path: "%s"\n        content: |\n' \
	  "/usr/share/backgrounds/ubuntu-default-dynamic.xml" >> $@
	@sed '/./s/^/          /' "$(SRC_DIR)/ubuntu-default-dynamic.xml" >> $@
	@# ubuntu-default-dynamic-meta.xml
	@printf '      # Dynamic wallpaper part 2/2.\n' >> $@
	@printf -- '      - path: "%s"\n        content: |\n' \
	  "/usr/share/gnome-background-properties/ubuntu-default-dynamic-meta.xml" >> $@
	@sed '/./s/^/          /' "$(SRC_DIR)/ubuntu-default-dynamic-meta.xml" >> $@
	@# ufw-custom-rules.ufw.ini
	@printf '      # UFW Configuration.\n' >> $@
	@printf -- '      - path: "%s"\n        content: |\n' \
	  "/etc/ufw/applications.d/ufw-custom-rules.ufw.ini" >> $@
	@sed '/./s/^/          /' "$(SRC_DIR)/ufw-custom-rules.ufw.ini" >> $@

.PHONY: $(LIB_DIR)/write_files_includes_server.yaml refresh-write-files-includes
$(LIB_DIR)/write_files_includes_server.yaml:
	@mkdir -pv $(dir $@)
	@printf -- '---\nwrite_files:\n' > $@
	@# logind.conf
	@printf '  # Suspend System to RAM when pressing the power button.\n' >> $@
	@printf '  # Without this, the setting in Gnome does not work.\n' >> $@
	@printf '  # cspell:ignore logind\n' >> $@
	@printf -- '  - path: "%s"\n    append: true\n    content: |\n' \
	  "/etc/systemd/logind.conf" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/logind.conf" >> $@
	@# 52unattended-upgrades-local.apt.conf
	@printf '  # Configure override for unattended-upgrades.\n' >> $@
	@printf -- '  - path: "%s"\n    content: |\n' \
	  "/etc/apt/apt.conf.d/52unattended-upgrades-local.conf" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/52unattended-upgrades-local.apt.conf" >> $@
	@# bashrc.sh
	@printf '  # Add ~/.local/bin to PATH, required at least for pipx.\n' >> $@
	@printf -- '  - path: "%s"\n    append: true\n    content: |\n' \
	  "/etc/skel/.bashrc" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/bashrc.sh" >> $@
	@# post_install_setup_server.sh
	@printf '  # Post-Installation Setup for users part 1/2.\n' >> $@
	@printf -- '  - path: "%s"\n    permissions: "0755"\n    content: |\n' \
	  "/etc/skel/post_install_setup.sh" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/post_install_setup_server.sh" >> $@

.PHONY: $(LIB_DIR)/write_files_includes_desktop.yaml
$(LIB_DIR)/write_files_includes_desktop.yaml:
	@mkdir -pv $(dir $@)
	@printf -- '---\nwrite_files:\n' > $@
	@# logind.conf
	@printf '  # Suspend System to RAM when pressing the power button.\n' >> $@
	@printf '  # Without this, the setting in Gnome does not work.\n' >> $@
	@printf '  # cspell:ignore logind\n' >> $@
	@printf -- '  - path: "%s"\n    append: true\n    content: |\n' \
	  "/etc/systemd/logind.conf" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/logind.conf" >> $@
	@# 52unattended-upgrades-local.apt.conf
	@printf '  # Configure override for unattended-upgrades.\n' >> $@
	@printf -- '  - path: "%s"\n    content: |\n' \
	  "/etc/apt/apt.conf.d/52unattended-upgrades-local.conf" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/52unattended-upgrades-local.apt.conf" >> $@
	@# bashrc.sh
	@printf '  # Add ~/.local/bin to PATH, required at least for pipx.\n' >> $@
	@printf -- '  - path: "%s"\n    append: true\n    content: |\n' \
	  "/etc/skel/.bashrc" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/bashrc.sh" >> $@
	@# post_install_setup_desktop.sh
	@printf '  # Post-Installation Setup for users part 1/2.\n' >> $@
	@printf -- '  - path: "%s"\n    permissions: "0755"\n    content: |\n' \
	  "/etc/skel/post_install_setup.sh" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/post_install_setup_desktop.sh" >> $@
	@# dconf_load.ini
	@printf '  # Post-Installation Setup for users part 2/2.\n' >> $@
	@printf '  # cspell:ignore weekdate luxon\n' >> $@
	@printf -- '  - path: "%s"\n    content: |\n' \
	  "/etc/skel/dconf_load.ini" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/dconf_load.ini" >> $@
	@# ubuntu-default-dynamic.xml
	@printf '  # Dynamic wallpaper part 1/2.\n' >> $@
	@printf '  # cspell:ignore starttime maoschanz\n' >> $@
	@printf -- '  - path: "%s"\n    content: |\n' \
	  "/usr/share/backgrounds/ubuntu-default-dynamic.xml" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/ubuntu-default-dynamic.xml" >> $@
	@# ubuntu-default-dynamic-meta.xml
	@printf '  # Dynamic wallpaper part 2/2.\n' >> $@
	@printf -- '  - path: "%s"\n    content: |\n' \
	  "/usr/share/gnome-background-properties/ubuntu-default-dynamic-meta.xml" >> $@
	@sed '/./s/^/      /' "$(SRC_DIR)/ubuntu-default-dynamic-meta.xml" >> $@

$(OUT_DIR)/rpi4_user-data_server.yaml: $(OUT_DIR)
	@yq eval-all '. as $$item ireduce ({}; . *+ $$item )' \
          "$(LIB_DIR)/00_header.yaml" \
	  "$(LIB_DIR)/packages.yaml" \
          "$(LIB_DIR)/write_files_includes_server.yaml" \
          "$(LIB_DIR)/shutdown.yaml" \
          > $@
	@#sed -i 's/__HOSTNAME__/other-host/' $@

$(OUT_DIR)/rpi4_user-data_desktop.yaml: $(OUT_DIR)
	@yq eval-all '. as $$item ireduce ({}; . *+ $$item )' \
          "$(LIB_DIR)/00_header.yaml" \
	  "$(LIB_DIR)/packages_u2404_desktop.yaml" \
          "$(LIB_DIR)/write_files_includes_desktop.yaml" \
          "$(LIB_DIR)/shutdown.yaml" \
          > $@
	@#sed -i 's/__HOSTNAME__/other-host/' $@

$(OUT_DIR):
	@mkdir -pv $(OUT_DIR)

$(OUT_DIR)/some_other_user_data_file.yaml: $(OUT_DIR)
	@yq eval-all '. as $$item ireduce ({}; . *+ $$item )' \
          "$(LIB_DIR)/00_header.yaml" \
          "$(LIB_DIR)/interactive.yaml" \
          "$(LIB_DIR)/apt.yaml" \
          "$(LIB_DIR)/codecs.yaml" \
          "$(LIB_DIR)/drivers_tpm_fde.yaml" \
          "$(LIB_DIR)/identity.yaml" \
          "$(LIB_DIR)/kernel.yaml" \
          "$(LIB_DIR)/keyboard.yaml" \
          "$(LIB_DIR)/locale.yaml" \
          "$(LIB_DIR)/oem.yaml" \
          "$(LIB_DIR)/source_tpm_fde.yaml" \
          "$(LIB_DIR)/ssh.yaml" \
          "$(LIB_DIR)/timezone.yaml" \
          "$(LIB_DIR)/updates.yaml" \
          "$(LIB_DIR)/packages.yaml" \
          "$(LIB_DIR)/snaps_desktop.yaml" \
          "$(LIB_DIR)/early_commands.yaml" \
          "$(LIB_DIR)/late_commands.yaml" \
          "$(LIB_DIR)/shutdown.yaml" \
          "$(LIB_DIR)/version.yaml" \
          "$(LIB_DIR)/user_data_write_files.yaml" \
          "$(LIB_DIR)/user_data_write_files_netplan.yaml" \
          "$(LIB_DIR)/user_data_write_files_includes.yaml" \
          > $@
	@sed -i 's/__HOSTNAME__/other-host/' $@
