#!/bin/bash
# cspell:ignore scriptslwbt ddns dfsd gext ucfq ssh-keygen PKFAIL LUKS NETDATA livewirebt ecdsa journalctl showformat iname flathub readvar luks cryptsetup tailscale netdata libexec freeipmi distro pkgs github syncthing

SSH_IMPORT_USER="change_me"

echo -e "\nOVERVIEW\n"

echo "- FETCH SSH AUTHORIZED KEYS"
echo "- PRINT SSH HOST KEY FINGERPRINTS"
echo "- SYSTEM STATUS"
echo "- GNOME CONFIGURATION"
echo "- GNOME EXTENSIONS"
echo "- CREATE SSH KEYS"
echo "- MISE"
echo "- TAILSCALE"
echo "- NETDATA"
echo "- DOTFILE DEPLOYMENT"
echo "- UFW FIREWALL CONFIGURATION"

echo -e "\nPlease, plug in your power cable before you continue.\n"

read -rp "> Continue with FETCH SSH AUTHORIZED KEYS? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  read -ri "${SSH_IMPORT_USER}" -ep "Launchpad username: " lp_user
  ssh-import-id-lp "${lp_user}"
fi

read -rp "> SSH host key FINGERPRINTS? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  for i in /etc/ssh/ssh_host_{rsa,ed25519,ecdsa}_key; do
    sudo ssh-keygen -l -f "$i"
  done
fi

read -rp "> Continue with SYSTEM STATUS? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  #systemctl --failed --no-pager
  systemctl --failed
  read -rp "Continue? "
  #systemctl list-timers --no-pager
  systemctl list-timers
  read -rp "Continue? "
  systemd-analyze blame
  journalctl -p 0..err
  read -rp "Continue? "
  cloud-init analyze show | less
  # shellcheck disable=SC2046
  sudo ucfq $(dpkg-query --show --showformat='${Package} ') | less
  sudo find "/etc/" -iname ".dpkg-" -o -iname ".ucf-"
  sudo grep --color=always -C 3 -i -E '(^[EW]:|error|warning)' "/var/log/cloud-init-output.log" | less -R
  sudo grep --color=always -C 1 -i -E '(^[EW]:|error|warning)' "/var/log/installer/"*".log" | less -R
  flatpak --user remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
  flatpak remotes --show-details
  snap list
  sudo unattended-upgrade --debug --dry-run
fi

read -rp "> Continue with GNOME CONFIGURATION? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  # Apply Gnome configuration
  dconf load / < "$HOME/dconf_load.ini"

  rm -v "$HOME/dconf_load.ini"
  echo -e "Note: You can find the main copy of this file in '/etc/skel/'.\n"
fi

read -rp "> Continue with GNOME EXTENSIONS? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  # Install helper tool gnome-extensions-cli
  pipx install gnome-extensions-cli

  # Install extension by UUID
  gext install date-menu-formatter@marcinjakubowski.github.com
  echo -e "Log out and back in to activate extensions."
fi

read -rp "> Continue with CREATE SSH KEYS? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  key_type="ed25519"
  id_file="${HOME}/.ssh/id_${key_type}_$(date +%F)"

  ssh-keygen \
    -t "${key_type}" \
    -C "${USER}@${HOSTNAME}-$(date +%F)" \
    -f "${id_file}" \
    | head -n 5 \
    | tail -n 3

  echo -e "\nAdd the new public key to GitHub before you continue."
  cat "${id_file}.pub"
  ssh-add
fi

read -rp "> Continue with MISE INSTALLATION? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  cd || exit
  curl -fsSL https://mise.run | sh
  # shellcheck disable=SC2016
  echo 'eval "$(~/.local/bin/mise activate bash)"' >> "${HOME}/.bashrc"
fi

read -rp "> Continue with TAILSCALE INSTALLATION? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  cd || exit
  curl -fsSL https://tailscale.com/install.sh | sh
  sudo tailscale up --qr
fi

read -rp "> Continue with NETDATA INSTALLATION? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  #cd; curl https://get.netdata.cloud/kickstart.sh > /tmp/netdata-kickstart.sh && sh /tmp/netdata-kickstart.sh --nightly-channel
  cd || exit
  curl https://get.netdata.cloud/kickstart.sh > /tmp/netdata-kickstart.sh && sh /tmp/netdata-kickstart.sh
  sudo /usr/libexec/netdata/netdata-updater.sh --enable-auto-updates
  sudo apt install -y netdata-plugin-freeipmi
fi

# Deploy dotfiles part 3 without deploy keys.
# Create SSH key before to access all repositories.
read -rp "> Continue with DOTFILE DEPLOYMENT? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  cd || exit
  curl -LO scriptslwbt.ddns.me/dfsd3-install.sh && bash dfsd3-install.sh
fi

read -rp "> Continue with UFW FIREWALL CONFIGURATION? (Y/n) " answer
if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then
  # Check if UFW is active.
  sudo ufw status numbered

  # UFW app profile list.
  sudo ufw app list

  # Enable app profiles in UFW.
  # TODO: Newline or zero delimiter for services.
  for service in $(sudo ufw app list | tail -n +2 | sed -e 's/^  //g'); do
    [[ "${service}" == "syncthing-gui" ]] && break

    read -rp "> Allow '${service}' in UFW? (Y/n) " answer
    if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then

      sudo ufw allow "${service}"
    fi
  done

  #for service in $(sudo ufw app list | tail -n +2 | sed -e 's/^  //g'); do
  #  # TODO: If list contains, else report.
  #  [[ "${service}" != "syncthing-gui" ]] && break
  #  # ...
  #done

  app_profile="syncthing-gui"
  for ipr in "100.0.0.0/8" "fd7a:115c:a1e0::/48"; do
    # TODO: If list contains, else report.

    read -rp "> Allow IP range '${ipr}' in UFW for ${app_profile}? (Y/n) " answer
    if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then

      sudo ufw allow from "${ipr}" to any app "${app_profile}"
    fi
  done

  sudo ufw enable

  sudo ufw status numbered
fi

rm -v "$HOME/post_install_setup.sh"
