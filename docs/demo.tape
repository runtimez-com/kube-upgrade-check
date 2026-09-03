# Recording of a real scan against a live cluster. Regenerate with:
#   vhs docs/demo.tape
#
# Nothing here is staged: the command runs against whatever kubeconfig context is named, and the
# output is whatever the tool found. If the demo ever stops matching the tool, the tool changed.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 950
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set BorderRadius 8

# The kubeconfig is set here rather than passed as a flag, so the visible command is the one a
# reader would actually type. It points at a throwaway copy of a single context, so recording the
# demo never touches the real kubeconfig.
Hide
Type "export PATH=$PWD/bin:$PATH KUBECONFIG=/tmp/demo-kubeconfig && clear" Enter
Show

Sleep 600ms
Type "kube-upgrade-check --target 1.34"
Sleep 500ms
Enter

# The scan itself takes a few seconds against a real API server; this waits for it rather than
# cutting away, because a demo that hides the latency is telling you something untrue.
Sleep 9s
