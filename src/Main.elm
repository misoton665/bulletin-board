import Html.App as Html

-- MVC
import Components.Model.Model exposing (initialModel)
import Components.View.View exposing (view)
import Components.Update.Update exposing (update)

-- APP
main : Program Never
main =
  Html.beginnerProgram { model = initialModel, view = view, update = update }
