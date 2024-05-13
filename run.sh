#!/bin/bash

# cspell:ignore luks BGRED raspi PBKDF sysfs pbkdf datasource resolv uuid noheadings bootable adiantum xchacha resizepart unxz crypttab zstd CRYPTTAB efivars xattrs nodeps nameserver imager cryptdevice cryptroot DESTDIR nproc cmdline mktemp CMDLINE dropbear FAKECLOUD DROPBEAR xtype zram keytype ecdsa hostkeys dropbearkey showpubkey postinst

# Minimal set of colors and styles.
export BGRED="\033[41m"
export NC="\033[0m"

# Display an error message passed as parameters with a timestamp.
#
# Usage advice for longer messages:
#
#   err_fatal \
#     "First line.\n" \
#     "Second line."
#
err() {
  echo >&2 -e "${BGRED}ERR${NC} $(date --rfc-3339=sec):\n $*"
}

# Display an error message passed as parameters with a timestamp and abort.
err_fatal() {
  echo >&2 -e "${BGRED}ERR${NC} $(date --rfc-3339=sec):\n $*"
  echo >&2 "Aborting."
  exit 1
}

# Test if a command exists. $1 = command name.
test_command() {
  command -v "$1" > /dev/null 2>&1
}

detect_gum_fatal() {
  if ! test_command "gum"; then
    err_fatal \
      "Found no utility 'gum' on \$PATH, aborting interactive mode.\n" \
      "See: https://github.com/charmbracelet/gum#installation"
  else
    echo "Found utility 'gum' on \$PATH, continuing in interactive mode."
  fi
}

enter_passphrase() {

  echo "Choose how to enter the initial LUKS passphrase:"
  form_choice="$(
    gum table -s "," -w 1,42 << EOF
n,Explanation
1,Passphrase visible with provided default
2,Passphrase masked with confirmation
EOF
  )"

  export GUM_INPUT_HEADER

  case "${form_choice%%,*}" in
    1)
      GUM_INPUT_HEADER="Customize the initial LUKS passphrase:"
      gum input --value="ubuntu" > "${passphrase_file}"
      ;;
    2)
      until cmp --silent "${passphrase_file}" "${passphrase_file}.confirm"; do
        GUM_INPUT_HEADER="Customize the initial LUKS passphrase:"
        gum input --password > "${passphrase_file}"
        GUM_INPUT_HEADER="Confirm the initial LUKS passphrase:"
        gum input --password > "${passphrase_file}.confirm"
      done

      dd if="/dev/urandom" of="${passphrase_file}.confirm" bs=512K count=1 2> "/dev/null"
      rm "${passphrase_file}.confirm"
      ;;
  esac
}

configure_interactive() {
  if [[ "${MODE}" == "interactive" ]]; then

    GUM_CHOOSE_HEADER="Choose a local image source:"
    export GUM_CHOOSE_HEADER
    mapfile -t local_images < <(
      find "${PWD}" -mindepth 1 -maxdepth 1 -xtype f -name "*raspi.img.xz" \
        -printf '%P\n'
    )

    [[ -z "${local_images[*]}" ]] && err_fatal "No local image found."
    IMAGE_SOURCE="$(gum choose "${local_images[@]}")"

    # TODO: Refactor this later to gum table, to provide explanations for the
    # options.
    GUM_CHOOSE_HEADER="Choose a configuration for the image:"
    MODEL_TARGET="$(gum choose "rpi4" "rpi5")"

    image_artifact="${IMAGE_SOURCE%%raspi.img.xz}raspi+luks+${MODEL_TARGET}+custom.img"

    GUM_CHOOSE_HEADER="Customize the value used for required PBKDF memory:"
    PBKDF_MEMORY=$(gum choose --selected=2048000 1024000 2048000 4096000 8192000)

    if [[ "${IMAGE_SOURCE}" =~ "preinstalled-server" ]]; then
      GUM_CHOOSE_HEADER="Do you want to install the 'ubuntu-desktop' package on the server image? (This can take more than 1 hour.)"
      INSTALL_DESKTOP="$(gum choose --selected="no" "yes" "no")"
    else
      INSTALL_DESKTOP="no"
    fi

    #GUM_CHOOSE_HEADER="Do you want to enable Cloud-Init on desktop?"
    #ENSURE_FAKECLOUD="$(gum choose "yes" "no")"
    ENSURE_FAKECLOUD="no"

    if [[ "${ENSURE_FAKECLOUD}" == "yes" ]]; then
      GUM_CHOOSE_HEADER="Do you want remove 'oem-config' from desktop?"
      REMOVE_OEM_CONFIG="$(gum choose --selected="no" "yes" "no")"
    else
      REMOVE_OEM_CONFIG="no"
    fi

    GUM_CHOOSE_HEADER="Do you want to compress the new image after building it?"
    COMPRESS_IMAGE="$(gum choose "yes" "yes (keep uncompressed image)" "no")"

    enter_passphrase

    export MODEL_TARGET IMAGE_SOURCE PBKDF_MEMORY COMPRESS_IMAGE ENSURE_FAKECLOUD REMOVE_OEM_CONFIG INSTALL_DESKTOP
    readonly MODEL_TARGET IMAGE_SOURCE PBKDF_MEMORY COMPRESS_IMAGE ENSURE_FAKECLOUD REMOVE_OEM_CONFIG INSTALL_DESKTOP
  fi
}

check_mode() {
  if [[ -z $1 ]]; then

    echo "No parameter provided, use 'rpi4' or 'rpi5' for non-interactive mode."
    detect_gum_fatal
    MODE="interactive"
    export MODE
    readonly MODE

  else

    case "$1" in
      "rpi4")
        MODEL_TARGET="$1"
        echo "Using configuration for '$1'."
        ;;
      "rpi5")
        MODEL_TARGET="$1"
        echo "Using configuration for '$1'."
        ;;
      *)
        err_fatal "Invalid input."
        ;;
    esac

    if [[ "$1" =~ "desktop" ]]; then
      INSTALL_DESKTOP="yes"
    else
      INSTALL_DESKTOP="no"
    fi

    IMAGE_SOURCE="$(
      find . -mindepth 1 -maxdepth 1 -type f -name "*raspi.img.xz" \
        -printf '%P\n' \
        | head -n1
    )"
    image_artifact="${IMAGE_SOURCE%%raspi.img.xz}raspi+luks+${MODEL_TARGET}.img"

    # Set initial LUKS passphrase to 'ubuntu'.
    echo "ubuntu" > "${passphrase_file}"

    PBKDF_MEMORY=2048000
    #ENSURE_FAKECLOUD="yes"
    ENSURE_FAKECLOUD="no"
    REMOVE_OEM_CONFIG="no"
    COMPRESS_IMAGE="yes"

    MODE="static"
    export MODE MODEL_TARGET IMAGE_SOURCE PBKDF_MEMORY COMPRESS_IMAGE ENSURE_FAKECLOUD REMOVE_OEM_CONFIG INSTALL_DESKTOP
    readonly MODE MODEL_TARGET IMAGE_SOURCE PBKDF_MEMORY COMPRESS_IMAGE ENSURE_FAKECLOUD REMOVE_OEM_CONFIG INSTALL_DESKTOP
  fi
}

prepare_images() {
  unxz --keep --verbose "${IMAGE_SOURCE}"

  cp -v "${IMAGE_SOURCE%%.xz}" "${image_base}"
  mv -v "${IMAGE_SOURCE%%.xz}" "${image_target}"

  if [[ "${INSTALL_DESKTOP}" == "yes" ]]; then
    dd_count=4
  else
    dd_count=1
  fi
  dd if="/dev/zero" bs=1G count="${dd_count}" >> "${image_target}"
  sudo parted --script --fix "${image_target}" resizepart 2 100%
}

mount_images_create_luks() {
  # shellcheck disable=SC2024
  sudo kpartx -avr "$PWD/${image_base}" > "${image_base}_mount.txt" || exit 1
  loop_base="$(
    head -n1 "${image_base}_mount.txt" \
      | sed -e 's/^add map //;s/p[0-9] .*//'
  )"
  rm -v "${image_base}_mount.txt"

  # shellcheck disable=SC2024
  sudo kpartx -av "$PWD/${image_target}" > "${image_target}_mount.txt" || exit 1
  loop_target="$(
    head -n1 "${image_target}_mount.txt" \
      | sed -e 's/^add map //;s/p[0-9] .*//'
  )"
  rm -v "${image_target}_mount.txt"

  # NOTE: We already executed it above, but we leave it here too.
  sudo mkdir -pv "${mnt_base}/"
  sudo mount -v --read-only "/dev/mapper/${loop_base}p2" "${mnt_base}/"

  # Why so complicated?
  # - https://unix.stackexchange.com/q/464090/cryptsetup-open-for-luks-improper-handling-of-key-file-argument
  # - Because cryptsetup does not stop reading on new line characters when using
  #   keyfiles.
  #
  case "${MODEL_TARGET}" in
    "rpi4")
      # Pi4 with at least 2GB of RAM
      tr -d '\r\n' < "${passphrase_file}" \
        | sudo cryptsetup luksFormat \
          --batch-mode --key-file=- \
          -c xchacha20,aes-adiantum-plain64 \
          --pbkdf-memory "${PBKDF_MEMORY}" --pbkdf-parallel=1 \
          "/dev/mapper/${loop_target}p2"
      ;;
    "rpi5")
      # Pi5
      #cat "${passphrase_file}" \
      #| tr -d '\r\n' \
      tr -d '\r\n' < "${passphrase_file}" \
        | sudo cryptsetup luksFormat \
          --batch-mode --key-file=- \
          --pbkdf-memory "${PBKDF_MEMORY}" --pbkdf-parallel=1 \
          "/dev/mapper/${loop_target}p2"
      ;;
    *)
      err_fatal "Invalid input."
      ;;
  esac

  tr -d '\r\n' < "${passphrase_file}" \
    | sudo cryptsetup luksOpen \
      --batch-mode --key-file=- \
      "/dev/mapper/${loop_target}p2" "${dev_decrypted}"

  # Copy contents to encrypted root.
  sudo mkfs.ext4 "/dev/mapper/${dev_decrypted}"
  sudo mkdir -pv "${mnt_chroot}/"
  sudo mount -v "/dev/mapper/${dev_decrypted}" "${mnt_chroot}/"
  sudo rsync \
    --acls \
    --archive \
    --hard-links \
    --info="progress2" \
    --numeric-ids \
    --one-file-system \
    --xattrs \
    "${mnt_base}/"* \
    "${mnt_chroot}/" \
    || exit 1

  # Prepare boot, proc, sysfs, dev and dev/pts for chroot.
  sudo mkdir -pv "${mnt_chroot}/boot/firmware/"
  sudo mkdir -pv "${mnt_chroot}/sysfs/"
  sudo mount -v "/dev/mapper/${loop_target}p1" "${mnt_chroot}/boot/firmware/"

  sudo mount -v -t "proc" none "${mnt_chroot}/proc/"
  sudo mount -v -t "sysfs" none "${mnt_chroot}/sys/"

  for i in "dev" "dev/pts"; do
    sudo mount -v -o bind "/${i}" "${mnt_chroot}/${i}/"
  done
}

# Prevent oem-config from removing certain packages.
fix_oem_config() {

  if [[ "${IMAGE_SOURCE}" =~ "preinstalled-desktop" ]]; then

    LANG=C sudo chroot "${mnt_chroot}/" "/bin/bash" << 'EOT'
apt-mark manual cryptsetup cryptsetup-initramfs lvm2 thin-provisioning-tools
EOT

  fi

}

# This function should only be used on desktops when Cloud-Init will be used to
# configure the installation.
remove_oem_config() {

  if [[ "${REMOVE_OEM_CONFIG}" == "yes" ]]; then

    # TODO: Remove '--quiet' when the bug with duplicated entries in
    # ubuntu.sources has bee resolved.
    LANG=C sudo chroot "${mnt_chroot}/" "/bin/bash" << 'EOT'
/usr/bin/time -f "%E %C" apt-get --yes --quiet autoremove --purge ubiquity oem-config
EOT

  fi

}

# The Raspberry Pi imager offers customization options based on Cloud-Init, but
# the desktop images are unable to pick up the NoCloud data source. With this
# function we ensure that the configuration file, which exists on the server
# image, will also exist on the desktop image.
# We leave it up to the user to use Cloud-Init or not, it is installed already
# to create SSH host keys.
ensure_cloud_init_fake_cloud_exists() {

  if [[ "${ENSURE_FAKECLOUD}" == "yes" ]]; then

    sudo tee "${mnt_chroot}/etc/cloud/cloud.cfg.d/99-fake-cloud.cfg" \
      > "/dev/null" << 'EOF'
# configure cloud-init for NoCloud
datasource_list: [ NoCloud, None ]
datasource:
  NoCloud:
    fs_label: system-boot
EOF

  fi
}

install_desktop() {

  if [[ "${INSTALL_DESKTOP}" == "yes" ]]; then

    echo "Starting to install 'ubuntu-desktop' package."

    # NOTE: Logs indicated that snapd should be installed before attempting to
    # install some "snapped" applications like Firefox.  NOTE: ubuntu-desktop
    # package installs a lot of packages and is not the the default anymore in
    # 24.04, ubuntu-desktop-raspi seems to be the right choice, but at first
    # glance ubuntu-desktop-minimal seem to provide a few more packages I
    # expect, however logs indicate that packages for the fingerprint reader
    # have issues and raspberry pis don't usually have a use case for
    # fingerprint readers. Further investigation needed for an optimal
    # solution.
    LANG=C sudo chroot "${mnt_chroot}/" "/bin/bash" << 'EOT'
mv -v "/etc/resolv.conf" "/etc/resolv.conf.bak"
echo "nameserver 8.8.8.8" | tee "/etc/resolv.conf" > /dev/null
/usr/bin/time -f "%E %C" apt-get update
/usr/bin/time -f "%E %C" apt-get --yes install snapd
/usr/bin/time -f "%E %C" apt-get --yes install language-pack-en pemmican-desktop ubuntu-desktop-minimal ubuntu-desktop-raspi ubuntu-raspi-settings-desktop
mv -v "/etc/resolv.conf.bak" "/etc/resolv.conf"
EOT

    image_artifact="${image_artifact%%.img}+desktop.img"

  fi

}

install_zram() {

  LANG=C sudo chroot "${mnt_chroot}/" "/bin/bash" << 'EOT'
mv -v "/etc/resolv.conf" "/etc/resolv.conf.bak"
echo "nameserver 8.8.8.8" | tee "/etc/resolv.conf" > /dev/null
/usr/bin/time -f "%E %C" apt-get update
/usr/bin/time -f "%E %C" apt-get --yes install zram-config
systemctl enable zram-config.service
mv -v "/etc/resolv.conf.bak" "/etc/resolv.conf"
EOT

}

make_new_root_bootable() {

  # LANG=C chroot /mnt/chroot/ /bin/bash
  # Q: Why move and replace resolv.conf?
  # A: because the link target "../run/systemd/resolve/stub-resolv.conf" is not
  #    valid in chroot.
  LANG=C sudo chroot "${mnt_chroot}/" "/bin/bash" << "EOT"
mv -v "/etc/resolv.conf" "/etc/resolv.conf.bak"
echo "nameserver 8.8.8.8" | tee "/etc/resolv.conf" > /dev/null
/usr/bin/time -f "%E %C" apt-get update
/usr/bin/time -f "%E %C" apt-get --yes install busybox cryptsetup dropbear-initramfs
for keytype in rsa ecdsa ed25519; do
    keyfile="/etc/dropbear/initramfs/dropbear_${keytype}_host_key";
    rm -v "${keyfile}";
done
mv -v "/etc/resolv.conf.bak" "/etc/resolv.conf"
EOT

  uuid_root="$(
    lsblk -o uuid --noheadings "/dev/mapper/${dev_decrypted}"
  )"
  uuid_luks="$(
    lsblk -o uuid --noheadings --nodeps "/dev/mapper/${loop_target}p2"
  )"

  # FSTAB
  sudo sed --in-place -e "s/LABEL=writable/UUID=${uuid_root}/" \
    "${mnt_chroot}/etc/fstab"

  # CRYPTTAB
  sudo tee -a "${mnt_chroot}/etc/crypttab" > "/dev/null" \
    <<< "${dev_decrypted} UUID=${uuid_luks} none luks,initramfs"

  # CMDLINE.TXT
  sudo sed --in-place -e \
    "s/root=LABEL=writable/root=\/dev\/mapper\/${dev_decrypted} cryptdevice=UUID=${uuid_luks}\:${dev_decrypted}/" \
    "${mnt_chroot}/boot/firmware/cmdline.txt"

  # DROPBEAR SCRIPT TO EXECUTE AFTER BOOT
  sudo tee "${mnt_chroot}/usr/local/bin/dropbear-luks.sh" \
    > "/dev/null" << 'EOF'
#!/bin/bash

# Copy your authorized_keys so that dropbear can use them on Raspberry Pi.

deb_dropbear_hostkeys_postinst() {
  # From:
  # https://git.launchpad.net/ubuntu/+source/dropbear/tree/debian/dropbear-initramfs.postinst
  #
  # generate host keys (excluding DSS)
  for keytype in rsa ecdsa ed25519; do
      keyfile="/etc/dropbear/initramfs/dropbear_${keytype}_host_key"
      echo "Generating Dropbear $(echo "$keytype" | tr '[a-z]' '[A-Z]') host key.  Please wait." >&2
      #dropbearkey -t "$keytype" -f "$keyfile" | showpubkey "$keyfile"
      sudo dropbearkey -t "$keytype" -f "$keyfile"
  done
}

deb_dropbear_hostkeys_postinst

# From: https://github.com/lwbt/ubuntu-rpi-luks
# Inspired by: https://github.com/ViRb3/pi-encrypted-boot-ssh

sudo mkdir -pv "/root/.ssh"
sudo cp -v "${HOME}/.ssh/authorized_keys" "/etc/dropbear/initramfs/authorized_keys"
sudo cp -v "${HOME}/.ssh/authorized_keys" "/root/.ssh/authorized_keys"
sudo chmod -v 0700 "/root/.ssh"
sudo chmod -v 0600 \
 "/etc/dropbear/initramfs/authorized_keys" \
 "/root/.ssh/authorized_keys"

/usr/bin/time -f "%E %C" sudo update-initramfs -u
sudo cp -v --dereference /boot/initrd.img /boot/firmware/initrd.img
EOF
  sudo chmod -v +x "${mnt_chroot}/usr/local/bin/dropbear-luks.sh"

  # DROPBEAR CONFIGURATION -- EXECUTE ONLY CRYPTROOT-UNLOCK
  sudo tee -a \
    "${mnt_chroot}/etc/dropbear/initramfs/dropbear.conf" > "/dev/null" \
    <<< "DROPBEAR_OPTIONS='-c cryptroot-unlock'"

  # INITRAMFS CONFIGURATION -- PART 1/3
  sudo tee -a \
    "${mnt_chroot}/etc/cryptsetup-initramfs/conf-hook" > "/dev/null" \
    <<< "CRYPTSETUP=y"

  # INITRAMFS CONFIGURATION -- PART 2/3
  # See ViRb3 instructions. We might only need this while creating the image on a
  # different host.
  sudo mkdir -pv \
    "${mnt_chroot}/usr/share/initramfs-tools/hooks.bak/"
  sudo cp -v \
    "${mnt_chroot}/usr/share/initramfs-tools/hooks/cryptroot" \
    "${mnt_chroot}/usr/share/initramfs-tools/hooks.bak/cryptroot"

  sudo patch --no-backup-if-mismatch \
    "${mnt_chroot}/usr/share/initramfs-tools/hooks/cryptroot" << 'EOF'
--- cryptroot
+++ cryptroot
@@ -33,7 +33,7 @@
         printf '%s\0' "$target" >>"$DESTDIR/cryptroot/targets"
         crypttab_find_entry "$target" || return 1
         crypttab_parse_options --missing-path=warn || return 1
-        crypttab_print_entry
+        printf '%s %s %s %s\n' "$_CRYPTTAB_NAME" "$_CRYPTTAB_SOURCE" "$_CRYPTTAB_KEY" "$_CRYPTTAB_OPTIONS" >&3
     fi
 }
EOF

  # INITRAMFS CONFIGURATION -- PART 3/3
  sudo sed -i 's/^TIMEOUT=.*/TIMEOUT=100/g' \
    "${mnt_chroot}/usr/share/cryptsetup/initramfs/bin/cryptroot-unlock"

  # UPDATE INITRAMFS IN CHROOT
  LANG=C sudo chroot "${mnt_chroot}/" "/bin/bash" << 'EOT'
/usr/bin/time -f "%E %C" update-initramfs -u
cp -v --dereference "/boot/initrd.img" "/boot/firmware/initrd.img"
EOT
  # TODO: Does not work, therefore copy with cp.
  #flash-kernel --force --verbose 6.8.0-1004-raspi

  # Revert back to original.
  sudo mv -v \
    "${mnt_chroot}/usr/share/initramfs-tools/hooks.bak/cryptroot" \
    "${mnt_chroot}/usr/share/initramfs-tools/hooks/cryptroot"
  sudo rmdir -v "${mnt_chroot}/usr/share/initramfs-tools/hooks.bak/"
}

apt_clean() {
  LANG=C sudo chroot "${mnt_chroot}/" "/bin/bash" << "EOT"
apt-get clean --yes
EOT
}

unmount_and_cleanup() {
  sudo umount "${mnt_chroot}/boot/firmware"
  sudo umount "${mnt_chroot}/sys/firmware/efi/efivars"
  sudo umount "${mnt_chroot}/sys"
  sudo umount "${mnt_chroot}/proc"
  sudo umount "${mnt_chroot}/dev/pts"
  sudo umount "${mnt_chroot}/dev"
  sudo umount "${mnt_chroot}"
  sudo cryptsetup close "${dev_decrypted}"
  sudo umount "${mnt_base}/"
  sudo rmdir "${mnt_chroot}"
  sudo rmdir "${mnt_base}"

  sudo kpartx -dv "$PWD/${image_base}"
  sudo kpartx -dv "$PWD/${image_target}"

  dd if="/dev/urandom" of="${passphrase_file}" bs=512K count=1 2> "/dev/null"
  rm "${passphrase_file}"

  # Avoid overwriting images.
  if [[ -f "${image_artifact}" || -f "${image_artifact}.zst" ]]; then
    image_artifact="${image_artifact%%.img}_$(date "+%F-%H%M%S").img"
  fi
  mv -v "${image_target}" "${image_artifact}"
  rm -v "${image_base}"

  if [[ "${COMPRESS_IMAGE}" == "yes" ]]; then
    zstd -15 --threads="$(nproc)" --rm "${image_artifact}"
  elif [[ "${COMPRESS_IMAGE}" == "yes (keep uncompressed image)" ]]; then
    zstd -15 --threads="$(nproc)" --keep "${image_artifact}"
  fi
}

main() {
  image_base="pi-base.img"
  image_target="pi-target.img"
  mnt_base="/mnt/${image_base%%.img}-root"
  mnt_chroot="/mnt/${image_target%%.img}-chroot"
  dev_decrypted="pi-root-decrypted"
  passphrase_file="$(mktemp)"

  check_mode "$1"
  configure_interactive

  # Just some activity to ask for the sudo password early.
  sudo mkdir -pv "${mnt_base}/"

  prepare_images
  mount_images_create_luks

  fix_oem_config
  # These don't work as intended, desktop is in a broken state when they are
  # executed in their current form, which is why the install_desktop function
  # was written to turn the server into a desktop.
  #remove_oem_config
  #ensure_cloud_init_fake_cloud_exists

  install_desktop
  install_zram

  make_new_root_bootable
  apt_clean
  unmount_and_cleanup
}

main "$@"
