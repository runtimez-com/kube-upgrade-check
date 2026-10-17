# The same real scan as demo.tape, run the way krew installs it: kubectl finds the binary as the
# plugin `kubectl-upgrade_check` and exposes it as `kubectl upgrade-check`. Regenerate with:
#   vhs docs/demo-krew.tape
#
# Nothing here is staged: the command runs against whatever kubeconfig context is named, and the
# output is whatever the tool found.

Output docs/demo-krew.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 950
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set BorderRadius 8

# The plugin name is a symlink to the built binary, which is exactly what krew installs. As in
# demo.tape, the kubeconfig is a throwaway copy of a single context.
Hide
Type "ln -sf kube-upgrade-check bin/kubectl-upgrade_check && export PATH=$PWD/bin:$PATH KUBECONFIG=/tmp/demo-kubeconfig && clear" Enter
Show

Sleep 600ms
Type "kubectl upgrade-check --target 1.38"
Sleep 500ms
Enter

Sleep 9s
