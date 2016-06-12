module Components.Update.Update exposing (
  Message(..), update
  )

import Components.Model.Model as M

-- UPDATE
type Message = Count | NoMessage

update : Message -> M.Model -> M.Model
update message (M.Model x) =
  case message of
    NoMessage -> M.Model x
    Count -> M.Model (x + 1)
