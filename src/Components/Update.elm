module Components.Update exposing (Message(..), update)

import Components.Model exposing (Model(..))

-- UPDATE
type Message = NoOp | Increment

update : Message -> Model -> Model
update msg (Model value) =
  case msg of
    NoOp -> Model value
    Increment -> Model <| value + 1