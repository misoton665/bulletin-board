module Components.Update.Update exposing (Message(..), update)

import Components.Model.Model as M

-- UPDATE
type Message = NoOp | Increment

update : Message -> M.Model -> M.Model
update msg (M.Model value) =
  case msg of
    NoOp -> M.Model value
    Increment -> M.Model <| value + 1