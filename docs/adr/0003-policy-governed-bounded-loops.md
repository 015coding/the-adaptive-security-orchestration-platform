# Policy-governed bounded loops

Workflow Nodes may use designer-configured Bounded Loops, but the Policy Engine validates their limits and no agent may increase them or create an open-ended loop. Each workflow run uses a Run Version; configuration changes during an active run must be versioned or approved, making runtime behavior both controlled and reconstructible.
