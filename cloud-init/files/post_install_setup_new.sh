#!/usr/bin/env bash
# cspell:ignore scriptslwbt ddns dfsd gext ucfq ssh-keygen PKFAIL LUKS NETDATA livewirebt ecdsa journalctl showformat iname flathub readvar luks cryptsetup tailscale netdata libexec freeipmi distro pkgs github syncthing
#
# TODO: Disabled as I know that there are failures but I want to always
# continue with the script.
#set -euo pipefail

SSH_IMPORT_USER="change_me"

# Print prompt and run provided action function if user confirms.
# Arguments:
#   $1 - Prompt string (e.g. "> Continue...? (Y/n) ")
#   $2 - Name of action function to call if confirmed
confirm_and_run() {
  local prompt="$1"
  local action_fn="$2"
  local answer

  # shellcheck disable=SC2034  # read -r uses variable
  read -r -n1 -p "$prompt" answer

  # Treat empty response as "yes"
  if [ -z "$answer" ] || [[ ! "$answer" =~ ^([Nn]|[Nn]o)$ ]]; then
    # Call the action function by name
    "$action_fn"
  fi

  echo
}

fetch_ssh_authorized_keys() {
  read -ri "${SSH_IMPORT_USER:-change_me}" -ep "Launchpad username: " lp_user
  ssh-import-id-lp "${lp_user}"
}

show_host_fingerprints() {
  for key in "/etc/ssh/ssh_host_"{rsa,ed25519,ecdsa}"_key"; do
    sudo ssh-keygen -l -f "$key"
  done
}

check_system_status() {
  # TODO: Check if the option without the pager is more user friendly.
  #systemctl --failed --no-pager
  systemctl --failed
  read -rp "Continue? "

  # TODO: Check if the option without the pager is more user friendly.
  #systemctl list-timers --no-pager
  systemctl list-timers
  read -rp "Continue? "

  systemd-analyze blame

  journalctl -p 0..err
  read -rp "Continue? "

  # Installation
  cloud-init analyze show | less

  # Package configuration artifacts
  # shellcheck disable=SC2046
  sudo ucfq $(dpkg-query --show --showformat='${Package} ') | less
  sudo find "/etc/" -iname ".dpkg-" -o -iname ".ucf-"

  # Installation errors
  sudo grep --color=always -C 3 -i -E '(^[EW]:|error|warning)' "/var/log/cloud-init-output.log" | less -R
  sudo grep --color=always -C 1 -i -E '(^[EW]:|error|warning)' "/var/log/installer/"*".log" | less -R

  # Packages
  flatpak --user remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
  flatpak remotes --show-details
  snap list

  # Upgrades
  sudo unattended-upgrade --debug --dry-run
}

check_pk_fail() {
  efi-readvar -v PK
}

snap2luks_passphrase() {
  pipx run --spec git+https://github.com/lwbt/python-snap2luks snap2luks --string "$(
    sudo snap recovery --show-keys | sed -e 's/recovery: \+//'
  )"

  # shellcheck disable=SC2046
  sudo cryptsetup luksAddKey --key-file "key.out" $(
    lsblk --paths --raw --output "name,label" \
      | grep "ubuntu-data-enc$" \
      | cut -d' ' -f1
  )

  rm -v "key.out"
}

gnome_configuration() {
  # Apply Gnome configuration
  dconf load / < "$HOME/dconf_load.ini"

  rm -v "$HOME/dconf_load.ini"
  echo -e "Note: You can find the main copy of this file in '/etc/skel/'.\n"
}

gnome_extensions() {
  # Install helper tool gnome-extensions-cli
  pipx install gnome-extensions-cli

  # Install extension by UUID
  gext install date-menu-formatter@marcinjakubowski.github.com
  echo -e "Log out and back in to activate extensions."
}

create_ssh_keys() {
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
}

mise_installation() {
  cd || exit
  curl -fsSL "https://mise.run" | sh
  # shellcheck disable=SC2016
  echo 'eval "$(~/.local/bin/mise activate bash)"' >> "${HOME}/.bashrc"
}

tailscale_installation() {
  cd || exit
  curl -fsSL "https://tailscale.com/install.sh" | sh
  sudo tailscale up --qr
}

netdata_installation() {
  cd || exit
  curl "https://get.netdata.cloud/kickstart.sh" > "/tmp/netdata-kickstart.sh" \
    && sh /tmp/netdata-kickstart.sh
  sudo /usr/libexec/netdata/netdata-updater.sh --enable-auto-updates
  sudo apt install -y netdata-plugin-freeipmi
}

dotfile_deployment() {
  cd || exit
  # TODO: Replace this, the domain is going away.
  #       Include a copy of the file in autoinstall if necessary.
  curl -LO scriptslwbt.ddns.me/dfsd3-install.sh && bash dfsd3-install.sh
}

ufw_firewall_configuration() {
  # Check if UFW is active.
  sudo ufw status numbered

  # UFW app profile list.
  sudo ufw app list

  # Enable app profiles in UFW.
  # TODO: Newline or zero delimiter for services.
  for service in $(sudo ufw app list | tail -n +2 | sed -e 's/^  //g'); do
    [[ "${service}" == "syncthing-gui" ]] && break

    read -r -n1 -p "> Allow '${service}' in UFW? (Y/n) " answer
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

    read -r -n1 -p "> Allow IP range '${ipr}' in UFW for ${app_profile}? (Y/n) " answer
    if [[ ! "${answer}" =~ (^[Nn]|^[Nn]"o") ]]; then

      sudo ufw allow from "${ipr}" to any app "${app_profile}"
    fi
  done

  sudo ufw enable

  sudo ufw status numbered
}

rm_post_install_file() {
  rm -v "${BASH_SOURCE[0]}"
}

echo -e "\nOVERVIEW\n"

echo "- FETCH SSH AUTHORIZED KEYS"
echo "- PRINT SSH HOST KEY FINGERPRINTS"
echo "- SYSTEM STATUS"
echo "- PKFAIL" # Put this after System Status
echo "- ADDITIONAL LUKS PASSPHRASE"
echo "- GNOME CONFIGURATION"
echo "- GNOME EXTENSIONS"
echo "- CREATE SSH KEYS"
echo "- MISE"
echo "- TAILSCALE"
echo "- NETDATA"
echo "- DOTFILE DEPLOYMENT"
echo "- UFW FIREWALL CONFIGURATION"

echo -e "\nNOTE: Please, plug in your power cable before you continue.\n"

confirm_and_run "> 01/13 Continue with FETCH SSH AUTHORIZED KEYS? (Y/n) " fetch_ssh_authorized_keys
confirm_and_run "> 02/13 Continue with SSH host key FINGERPRINTS? (Y/n) " show_host_fingerprints
confirm_and_run "> 03/13 Continue with SYSTEM STATUS? (Y/n) " check_system_status
confirm_and_run "> 04/13 Check for PKfail? (Y/n) " check_pk_fail
confirm_and_run "> 05/13 Continue with create ADDITIONAL LUKS PASSPHRASE? (Y/n) " snap2luks_passphrase
confirm_and_run "> 06/13 Continue with GNOME CONFIGURATION? (Y/n) " gnome_configuration
confirm_and_run "> 07/13 Continue with GNOME EXTENSIONS? (Y/n) " gnome_extensions
confirm_and_run "> 08/13 Continue with CREATE SSH KEYS? (Y/n) " create_ssh_keys
confirm_and_run "> 09/13 Continue with MISE INSTALLATION? (Y/n) " mise_installation
confirm_and_run "> 10/13 Continue with TAILSCALE INSTALLATION? (Y/n) " tailscale_installation
confirm_and_run "> 11/13 Continue with NETDATA INSTALLATION? (Y/n) " netdata_installation
confirm_and_run "> 12/13 Continue with DOTFILE DEPLOYMENT? (Y/n) " dotfile_deployment
confirm_and_run "> 13/13 Continue with UFW FIREWALL CONFIGURATION? (Y/n) " ufw_firewall_configuration

echo

confirm_and_run "Finished. Remove file '${BASH_SOURCE[0]}'? (Y/n) " rm_post_install_file
