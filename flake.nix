{
  description = "php2shell-scanner";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      forAllSystems = with nixpkgs; (lib.genAttrs lib.systems.flakeExposed);
      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python3Packages = pkgs.python3Packages;
        in
        {
          default = python3Packages.buildPythonApplication {
            pname = "php2shell-scanner";
            version = "0.1.0";
            pyproject = true;
            src = ./.;

            build-system = [ python3Packages.setuptools ];

            # amass and nuclei are invoked at runtime; put them on PATH.
            makeWrapperArgs = [
              "--prefix"
              "PATH"
              ":"
              (pkgs.lib.makeBinPath [
                pkgs.amass
                pkgs.nuclei
              ])
            ];

            # run.py locates php2shell.yaml and paths.txt next to itself via
            # __file__, so install them alongside the module in site-packages.
            postInstall = ''
              cp php2shell.yaml paths.txt "$out/${python3Packages.python.sitePackages}/"
            '';

            doCheck = false;
          };
        }
      );

      inherit formatter;
    };
}
