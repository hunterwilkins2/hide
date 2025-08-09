# Hide Secret Manager

PGP encrypted secrets store

## Install

```sh
go install github.com/hunterwilkins2/hide@v0.1.0
```

## Usage

```sh
PGP encrypted secrets store

Usage:
  hide [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  get         Get secrets from store
  help        Help about any command
  list        Lists all secrets within store
  pkl         pkl language binding
  remove      Removes secrets from store
  set         Sets/Updates secrets within store

Flags:
  -h, --help                     help for hide
      --pgp-private-key string   PGP private key (default "/home/hunter/.local/share/hide/hide-private-key.asc")
  -s, --store string             path to secrets store (default "hide.enc.env")
  -v, --version                  version for hide

Use "hide [command] --help" for more information about a command.
```

## Pkl Language Binding

`hide` can be used as an external resource reader for [pkl](https://pkl-lang.org/index.html) to securely read secrets into environment files. 

```pkl
// Read single value from Hide secret store 
DBPassword = read("hide:DB_PASSWORD").text

// Read multiple globbed values from Hide secret store 
// and convert to pkl Mapping
ApiKeys = new {
  for (_key in read*("hide:API_*_KEY")) {
	  [_key.uri.replaceFirst("hide:", "")] = _key.text
	}
}
```

```sh
$ pkl eval test.pkl \
    --allowed-resources=hide,prop \
    --external-resource-reader=hide='hide pkl'

DBPassword = "pa55word"
ApiKeys {
  ["API_PRIVATE_KEY"] = "abcdefghi"
  ["API_PUBLIC_KEY"] = "123456789"
}
```


