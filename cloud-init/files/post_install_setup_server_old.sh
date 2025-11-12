#!/bin/bash
# cspell:ignore scriptslwbt ddns dfsd gext ucfq ssh-keygen PKFAIL LUKS NETDATA livewirebt ecdsa journalctl showformat iname flathub readvar luks cryptsetup tailscale netdata libexec freeipmi distro pkgs github syncthing

SSH_IMPORT_USER="change_me"

echo -e "\nOVERVIEW\n"

echo "- CREATE SSH KEYS"
echo "- MISE"
echo "- TAILSCALE"
echo "- NETDATA"
echo "- DOTFILE DEPLOYMENT"
echo "- UFW FIREWALL CONFIGURATION"

echo -e "\nPlease, plug in your power cable before you continue.\n"

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
