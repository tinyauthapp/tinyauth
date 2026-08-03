package main

import (
	"log/slog"
	"reflect"
)

func main() {
	slog.Info("generating example env file")
	generateExampleEnv()
	slog.Info("generating config reference markdown file")
	generateMarkdown()
}

func walkAndBuild[T any](parent reflect.Type, parentValue reflect.Value,
	parentPath string, entries *[]T,
	buildEntry func(child reflect.StructField, childValue reflect.Value, parentPath string, entries *[]T),
	buildMap func(child reflect.StructField, parentPath string, entries *[]T),
	buildChildPath func(parentPath string, childName string) string,
) {
	for i := 0; i < parent.NumField(); i++ {
		field := parent.Field(i)
		fieldType := field.Type
		fieldValue := parentValue.Field(i)

		switch fieldType.Kind() {
		case reflect.Struct:
			childPath := buildChildPath(parentPath, field.Name)
			walkAndBuild[T](fieldType, fieldValue, childPath, entries, buildEntry, buildMap, buildChildPath)
		case reflect.Map:
			buildMap(field, parentPath, entries)
		case reflect.Bool, reflect.String, reflect.Slice, reflect.Int:
			buildEntry(field, fieldValue, parentPath, entries)
		default:
			slog.Info("unknown type", "type", fieldType.Kind())
		}
	}
}
