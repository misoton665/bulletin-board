module Components.Update.Update exposing (Message, update)

import Components.Model.Model as M

type Page = Home | RegisterNewUser | UserProfile

type Action a = PageTransition Page | LocalEvent a

type NoEvent = NoEvent

type alias TransitAction = Action NoEvent

-- UPDATE
type alias Message a = (Action a)

update : Message a -> M.Model -> M.Model
update msg (M.Model value) =
  case msg of
    (PageTransition page) -> M.Model value
    (LocalEvent NoEvent) -> M.Model <| value + 1