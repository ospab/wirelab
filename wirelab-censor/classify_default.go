//go:build !ndpi

package main

// Without the ndpi build tag the censor recognises protocols by their first
// bytes only (see builtinClassifier).
func defaultClassifier() Classifier { return newBuiltinClassifier() }
