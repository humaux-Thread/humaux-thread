use crate::read_gate::visibility_readable;
use humaux_domain::identity::{AuthorizationScope, VisibilityDescriptor};

fn f(a: &AuthorizationScope, m: &VisibilityDescriptor) -> bool {
    visibility_readable(a, m)
}
