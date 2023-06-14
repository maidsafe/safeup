#!/usr/bin/env just --justfile

release_repo := "maidsafe/safeup"

build-release-artifacts arch:
  #!/usr/bin/env bash
  set -e

  arch="{{arch}}"
  supported_archs=(
    "x86_64-pc-windows-msvc"
    "x86_64-apple-darwin"
    "x86_64-unknown-linux-musl"
    "arm-unknown-linux-musleabi"
    "armv7-unknown-linux-musleabihf"
    "aarch64-unknown-linux-musl"
  )

  arch_supported=false
  for supported_arch in "${supported_archs[@]}"; do
    if [[ "$arch" == "$supported_arch" ]]; then
      arch_supported=true
      break
    fi
  done

  if [[ "$arch_supported" == "false" ]]; then
    echo "$arch is not supported."
    exit 1
  fi

  if [[ "$arch" == "x86_64-unknown-linux-musl" ]]; then
    if [[ "$(grep -E '^NAME="Ubuntu"' /etc/os-release)" ]]; then
      # This is intended for use on a fresh Github Actions agent
      sudo apt update -y
      sudo apt install -y musl-tools
    fi
    rustup target add x86_64-unknown-linux-musl
  fi

  rm -rf artifacts
  mkdir artifacts
  cargo clean
  if [[ $arch == arm* || $arch == armv7* || $arch == aarch64* ]]; then
    cargo install cross
    cross build --release --target $arch --bin safeup
  else
    cargo build --release --target $arch --bin safeup
  fi

  find target/$arch/release -maxdepth 1 -type f -exec cp '{}' artifacts \;
  rm -f artifacts/.cargo-lock

package-release-assets:
  #!/usr/bin/env bash
  set -e

  architectures=(
    "x86_64-pc-windows-msvc"
    "x86_64-apple-darwin"
    "x86_64-unknown-linux-musl"
    "arm-unknown-linux-musleabi"
    "armv7-unknown-linux-musleabihf"
    "aarch64-unknown-linux-musl"
  )
  bin="safeup"
  version=$(cat Cargo.toml | grep "^version" | awk -F '=' '{ print $2 }' | xargs)

  rm -rf deploy/$bin
  find artifacts/ -name "$bin" -exec chmod +x '{}' \;
  for arch in "${architectures[@]}" ; do
    echo "Packaging for $arch..."
    if [[ $arch == *"windows"* ]]; then bin_name="${bin}.exe"; else bin_name=$bin; fi
    zip -j $bin-$version-$arch.zip artifacts/$arch/release/$bin_name
    tar -C artifacts/$arch/release -zcvf $bin-$version-$arch.tar.gz $bin_name
  done

  mkdir -p deploy/$bin
  mv *.tar.gz deploy/$bin
  mv *.zip deploy/$bin

upload-release-assets:
  #!/usr/bin/env bash
  set -e
  version=$(cat Cargo.toml | grep "^version" | awk -F '=' '{ print $2 }' | xargs)
  echo "Uploading assets to release..."
  cd deploy/safeup
  ls | xargs gh release upload "v${version}" --repo {{release_repo}}

upload-release-assets-to-s3:
  #!/usr/bin/env bash
  set -e

  cd deploy/safeup
  for file in *.zip *.tar.gz; do
    aws s3 cp "$file" "s3://sn-safeup/$file" --acl public-read
  done
