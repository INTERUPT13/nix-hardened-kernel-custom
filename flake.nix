{
  description = "flake for building a custom hardened kernel with some additional hardening flags";

  inputs = {
    # irrelevant as long as we use nixos's hardened kernel [patches]
    #linux-src = {
    #  url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git";
    #  type = "git";
    #  flake = false;
    #};
  };

  outputs = { self, nixpkgs}: with nixpkgs; #,linux-src }: with nixpkgs;
  let
    kernels = legacyPackages.x86_64-linux.linuxKernel.kernels;
  in {

    packages.x86_64-linux.custom_hardened_kernel = kernels.linux_hardened.override {
     # since we want the patches that nixos's hardened kernel already
     # provides as for now. Using custom src wont work
     #argsOverride = {
     #  src = linux-src;
     #};
     structuredExtraConfig = 
     import ./hardened_config.nix {
       lib = lib;
       version = kernels.linux_hardened.version;
     };
   };

    defaultPackage.x86_64-linux = self.packages.x86_64-linux.custom_hardened_kernel;

  };

}
