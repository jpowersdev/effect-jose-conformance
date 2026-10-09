{
  description = "Conformance tests for effect/jose across JavaScript runtimes";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs = {nixpkgs, ...}: let
    systems = ["aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

    runtimes = pkgs: {
      node22 = {
        expected = "node@22";
        command = "${pkgs.nodejs_22}/bin/node";
      };
      node24 = {
        expected = "node@24";
        command = "${pkgs.nodejs_24}/bin/node";
      };
      node26 = {
        expected = "node@26";
        command = "${pkgs.nodejs_26}/bin/node";
      };
      deno = {
        expected = "deno";
        command = "${pkgs.deno}/bin/deno run -A";
      };
      bun = {
        expected = "bun";
        command = "${pkgs.bun}/bin/bun --bun";
      };
    };

    # Shared environment: the Playwright browsers built by nixpkgs. The npm
    # `playwright` version in package.json must match `playwright-driver`.
    env = pkgs: ''
      export PLAYWRIGHT_BROWSERS_PATH=${pkgs.playwright-driver.browsers}
      export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
      export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
    '';

    # Installs dependencies with a pinned Node.js and pnpm when missing.
    ensureInstalled = pkgs: ''
      if [ ! -d node_modules ] || [ ! -e node_modules/.modules.yaml ]; then
        git submodule update --init vendor/effect
        PATH=${pkgs.nodejs_24}/bin:$PATH ${pkgs.pnpm}/bin/pnpm install --frozen-lockfile
      fi
    '';

    vitest = "node_modules/vitest/vitest.mjs run";

    apps = pkgs: let
      app = name: text: {
        type = "app";
        program = "${pkgs.writeShellApplication {
          inherit name;
          runtimeInputs = [pkgs.git];
          text = ''
            ${env pkgs}
            ${ensureInstalled pkgs}
            ${text}
          '';
        }}/bin/${name}";
      };
      serverApp = name: runtime:
        app "test-${name}" ''
          EXPECTED_RUNTIME=${runtime.expected} ${runtime.command} ${vitest} --project server "$@"
        '';
      serverApps = nixpkgs.lib.mapAttrs' (name: runtime: nixpkgs.lib.nameValuePair "test-${name}" (serverApp name runtime)) (runtimes pkgs);
      runAll = nixpkgs.lib.concatMapStringsSep "\n" (name: let
        runtime = (runtimes pkgs).${name};
      in ''
        echo "==> ${name}"
        EXPECTED_RUNTIME=${runtime.expected} ${runtime.command} ${vitest} --project server "$@" || failed+=("${name}")
      '') (builtins.attrNames (runtimes pkgs));
    in
      serverApps
      // {
        test-browsers = app "test-browsers" ''
          ${pkgs.nodejs_24}/bin/node ${vitest} --project browser "$@"
        '';
        test-all = app "test-all" ''
          failed=()
          ${runAll}
          echo "==> browsers"
          ${pkgs.nodejs_24}/bin/node ${vitest} --project browser "$@" || failed+=("browsers")
          if [ ''${#failed[@]} -gt 0 ]; then
            echo "Failed: ''${failed[*]}"
            exit 1
          fi
          echo "All runtimes passed."
        '';
      };
  in {
    apps = forAllSystems apps;

    devShells = forAllSystems (pkgs: {
      default = pkgs.mkShell {
        packages = with pkgs; [nodejs_24 pnpm deno bun];
        shellHook = env pkgs;
      };
    });

    formatter = forAllSystems (pkgs: pkgs.alejandra);
  };
}
