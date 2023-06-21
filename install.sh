#!/bin/bash

set -e

install_client=0
install_node=0

while (( "$#" )); do
  case "$1" in
    --client)
      install_client=1
      shift
      ;;
    --node)
      install_node=1
      shift
      ;;
    *) 
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ $EUID -eq 0 ]]; then
  running_as_root=1
else
  running_as_root=0
fi

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
    arm64*)
      if [[ $os == "mac" ]]; then
        echo "Mac arm64 architecture not supported, installing x86_64 version"
        arch_triple="x86_64-apple-darwin"
      else
        arch_triple="aarch64-unknown-$os-musl"
      fi
      ;;
    armv7*) arch_triple="armv7-unknown-$os-musleabihf" ;;
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
  if [[ $running_as_root -eq 1 ]]; then
    target_dir="/usr/local/bin"
  else
    target_dir="$HOME/.local/bin"
    mkdir -p "$target_dir"
    mkdir -p "$HOME/.config/safe"
    cat << 'EOF' > ~/.config/safe/env
#!/bin/sh
case ":${PATH}:" in
    *:"$HOME/.local/bin":*)
        ;;
    *)
        export PATH="$HOME/.local/bin:$PATH"
        ;;
esac
EOF
  echo "source $HOME/.config/safe/env" >> "$HOME/.bashrc"
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
  if [[ $install_client -eq 1 ]]; then
    echo "Now running safeup to install the safe client..."
    $target_dir/safeup client
  fi
  if [[ $install_node -eq 1 ]]; then
    echo "Now running safeup to install safenode..."
    $target_dir/safeup node
  fi
  if [[ $running_as_root -eq 1 ]]; then
    echo "Please run 'safeup --help' to see how to install network components."
  else
    printf "\n"
    echo "The safeup binary has been installed, but it's not available in this session."
    echo "You must either run 'source ~/.config/safe/env' in this session, or start a new session."
    echo "When safeup is available, please run 'safeup --help' to see how to install network components."
  fi
}

print_banner
detect_os
detect_arch
get_latest_version
install_safeup
post_install
