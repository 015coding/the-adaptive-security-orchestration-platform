# Raw model data access in the first version

The first version permits a configured AI model to receive raw target data and Sensitive Evidence. Each invocation must still create a Model Call Record so the Execution Trail identifies the provider, model version, requesting node, and data-access decision; later versions may add redaction-by-default or local-model options.
