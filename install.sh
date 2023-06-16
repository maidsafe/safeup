#!/bin/bash

function print_banner() {
  echo "**************************************"
  echo "*                                    *"
  echo "*         Installing safeup          *"
  echo "*                                    *"
  echo "**************************************"
}

function detect_os() {
  os=$(uname -s)
  case "$os" in
    Linux*) os=linux ;;
    Darwin*) os=mac ;;
    *) echo "Unknown operating system"; exit 1 ;;
  esac
}

function detect_arch() {
  arch=$(uname -m)
  case "$arch" in
    x86_64*) 
      if [[ $os == "mac" ]]; then
        arch_triple="x86_64-apple-darwin"
      else
        arch_triple="x86_64-unknown-$os-musl"
      fi
      ;;
    aarch64*) arch_triple="aarch64-unknown-$os-musl" ;;
    *) echo "Architecture $arch not supported"; exit 1 ;;
  esac
  echo "Will retrieve safeup for $arch_triple architecture"
}

function get_latest_version() {
  release_data=$(curl --silent "https://api.github.com/repos/maidsafe/safeup/releases/latest")
  version=$(echo "$release_data" | awk -F': ' '/"tag_name":/ {print $2}' | \
    sed 's/"//g' | sed 's/,//g' | sed 's/v//g')
  download_url=$(echo "$release_data" | \
    awk -F': ' '/"browser_download_url":/ {print $2 $3}' | \
    grep "safeup-$version-$arch_triple.tar.gz" | sed 's/"//g' | sed 's/,//g')
  echo "Latest version of safeup is $version"
}

function install_safeup() {
  if [[ $EUID -eq 0 ]]; then
    target_dir="/usr/local/bin"
  else
    target_dir="$HOME/.local/bin"
    mkdir -p "$target_dir"
  fi

  temp_dir=$(mktemp -d)
  curl -L "$download_url" -o "$temp_dir/safeup.tar.gz"
  tar -xzf "$temp_dir/safeup.tar.gz" -C "$temp_dir"
  mv "$temp_dir/safeup" "$target_dir/safeup"
  chmod +x "$target_dir/safeup"
  rm -rf "$temp_dir"
  echo "safeup installed to $target_dir/safeup"
}

function post_install() {
  echo "Now running safeup to install the safe client..."
  $target_dir/safeup client
  if [[ $EUID -eq 0 ]]; then
    echo "If you wish to install safenode, please run 'sudo safeup node'."
  else
    echo "If you wish to install safenode, please run 'safeup node'."
  fi
}

print_banner
detect_os
detect_arch
get_latest_version
install_safeup
post_install
