# Templating
Rather than using vualt's identity templates this plugin uses standard mustache templating.

https://github.com/hoisie/mustache

## Example:

```go
tmpl,_ := mustache.ParseString("hello {{c}}")
var buf bytes.Buffer;
for i := 0; i < 10; i++ {
    tmpl.Render (map[string]string { "c":"world"}, &buf)  
}
```