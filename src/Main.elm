import Html.App as Html

-- component import example
import Components.Model exposing (..)
import Components.View exposing (..)
import Components.Update exposing (..)

-- APP
main : Program Never
main =
  Html.beginnerProgram { model = initialModel, view = view, update = update }
