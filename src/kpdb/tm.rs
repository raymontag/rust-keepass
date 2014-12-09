pub struct Tm {
    pub year:   i32,
    pub month:  i32,
    pub day:    i32,
    pub hour:   i32,
    pub minute: i32,
    pub second: i32,
}

impl Tm {
    pub fn new() -> Tm {
        Tm { year:   0,
             month:  0,
             day:    0,
             hour:   0,
             minute: 0,
             second: 0,
        }
    }
}

