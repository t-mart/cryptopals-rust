pub(crate) enum B64Sextet {
    Pad,
    Sextet(u8),
    Invalid,
}

use B64Sextet::{Invalid, Pad, Sextet};

pub(crate) const BASE64_DECODE_TABLE: [B64Sextet; 256] = [
    Invalid,    // 0
    Invalid,    // 1
    Invalid,    // 2
    Invalid,    // 3
    Invalid,    // 4
    Invalid,    // 5
    Invalid,    // 6
    Invalid,    // 7
    Invalid,    // 8
    Invalid,    // 9
    Invalid,    // 10
    Invalid,    // 11
    Invalid,    // 12
    Invalid,    // 13
    Invalid,    // 14
    Invalid,    // 15
    Invalid,    // 16
    Invalid,    // 17
    Invalid,    // 18
    Invalid,    // 19
    Invalid,    // 20
    Invalid,    // 21
    Invalid,    // 22
    Invalid,    // 23
    Invalid,    // 24
    Invalid,    // 25
    Invalid,    // 26
    Invalid,    // 27
    Invalid,    // 28
    Invalid,    // 29
    Invalid,    // 30
    Invalid,    // 31
    Invalid,    // 32
    Invalid,    // 33
    Invalid,    // 34
    Invalid,    // 35
    Invalid,    // 36
    Invalid,    // 37
    Invalid,    // 38
    Invalid,    // 39
    Invalid,    // 40
    Invalid,    // 41
    Invalid,    // 42
    Sextet(62), // 43 (+)
    Invalid,    // 44
    Invalid,    // 45
    Invalid,    // 46
    Sextet(63), // 47 (/)
    Sextet(52), // 48 (0)
    Sextet(53), // 49 (1)
    Sextet(54), // 50 (2)
    Sextet(55), // 51 (3)
    Sextet(56), // 52 (4)
    Sextet(57), // 53 (5)
    Sextet(58), // 54 (6)
    Sextet(59), // 55 (7)
    Sextet(60), // 56 (8)
    Sextet(61), // 57 (9)
    Invalid,    // 58
    Invalid,    // 59
    Invalid,    // 60
    Pad,        // 61 (=)
    Invalid,    // 62
    Invalid,    // 63
    Invalid,    // 64
    Sextet(0),  // 65 (A)
    Sextet(1),  // 66 (B)
    Sextet(2),  // 67 (C)
    Sextet(3),  // 68 (D)
    Sextet(4),  // 69 (E)
    Sextet(5),  // 70 (F)
    Sextet(6),  // 71 (G)
    Sextet(7),  // 72 (H)
    Sextet(8),  // 73 (I)
    Sextet(9),  // 74 (J)
    Sextet(10), // 75 (K)
    Sextet(11), // 76 (L)
    Sextet(12), // 77 (M)
    Sextet(13), // 78 (N)
    Sextet(14), // 79 (O)
    Sextet(15), // 80 (P)
    Sextet(16), // 81 (Q)
    Sextet(17), // 82 (R)
    Sextet(18), // 83 (S)
    Sextet(19), // 84 (T)
    Sextet(20), // 85 (U)
    Sextet(21), // 86 (V)
    Sextet(22), // 87 (W)
    Sextet(23), // 88 (X)
    Sextet(24), // 89 (Y)
    Sextet(25), // 90 (Z)
    Invalid,    // 91
    Invalid,    // 92
    Invalid,    // 93
    Invalid,    // 94
    Invalid,    // 95
    Invalid,    // 96
    Sextet(26), // 97 (a)
    Sextet(27), // 98 (b)
    Sextet(28), // 99 (c)
    Sextet(29), // 100 (d)
    Sextet(30), // 101 (e)
    Sextet(31), // 102 (f)
    Sextet(32), // 103 (g)
    Sextet(33), // 104 (h)
    Sextet(34), // 105 (i)
    Sextet(35), // 106 (j)
    Sextet(36), // 107 (k)
    Sextet(37), // 108 (l)
    Sextet(38), // 109 (m)
    Sextet(39), // 110 (n)
    Sextet(40), // 111 (o)
    Sextet(41), // 112 (p)
    Sextet(42), // 113 (q)
    Sextet(43), // 114 (r)
    Sextet(44), // 115 (s)
    Sextet(45), // 116 (t)
    Sextet(46), // 117 (u)
    Sextet(47), // 118 (v)
    Sextet(48), // 119 (w)
    Sextet(49), // 120 (x)
    Sextet(50), // 121 (y)
    Sextet(51), // 122 (z)
    Invalid,    // 123
    Invalid,    // 124
    Invalid,    // 125
    Invalid,    // 126
    Invalid,    // 127
    Invalid,    // 128
    Invalid,    // 129
    Invalid,    // 130
    Invalid,    // 131
    Invalid,    // 132
    Invalid,    // 133
    Invalid,    // 134
    Invalid,    // 135
    Invalid,    // 136
    Invalid,    // 137
    Invalid,    // 138
    Invalid,    // 139
    Invalid,    // 140
    Invalid,    // 141
    Invalid,    // 142
    Invalid,    // 143
    Invalid,    // 144
    Invalid,    // 145
    Invalid,    // 146
    Invalid,    // 147
    Invalid,    // 148
    Invalid,    // 149
    Invalid,    // 150
    Invalid,    // 151
    Invalid,    // 152
    Invalid,    // 153
    Invalid,    // 154
    Invalid,    // 155
    Invalid,    // 156
    Invalid,    // 157
    Invalid,    // 158
    Invalid,    // 159
    Invalid,    // 160
    Invalid,    // 161
    Invalid,    // 162
    Invalid,    // 163
    Invalid,    // 164
    Invalid,    // 165
    Invalid,    // 166
    Invalid,    // 167
    Invalid,    // 168
    Invalid,    // 169
    Invalid,    // 170
    Invalid,    // 171
    Invalid,    // 172
    Invalid,    // 173
    Invalid,    // 174
    Invalid,    // 175
    Invalid,    // 176
    Invalid,    // 177
    Invalid,    // 178
    Invalid,    // 179
    Invalid,    // 180
    Invalid,    // 181
    Invalid,    // 182
    Invalid,    // 183
    Invalid,    // 184
    Invalid,    // 185
    Invalid,    // 186
    Invalid,    // 187
    Invalid,    // 188
    Invalid,    // 189
    Invalid,    // 190
    Invalid,    // 191
    Invalid,    // 192
    Invalid,    // 193
    Invalid,    // 194
    Invalid,    // 195
    Invalid,    // 196
    Invalid,    // 197
    Invalid,    // 198
    Invalid,    // 199
    Invalid,    // 200
    Invalid,    // 201
    Invalid,    // 202
    Invalid,    // 203
    Invalid,    // 204
    Invalid,    // 205
    Invalid,    // 206
    Invalid,    // 207
    Invalid,    // 208
    Invalid,    // 209
    Invalid,    // 210
    Invalid,    // 211
    Invalid,    // 212
    Invalid,    // 213
    Invalid,    // 214
    Invalid,    // 215
    Invalid,    // 216
    Invalid,    // 217
    Invalid,    // 218
    Invalid,    // 219
    Invalid,    // 220
    Invalid,    // 221
    Invalid,    // 222
    Invalid,    // 223
    Invalid,    // 224
    Invalid,    // 225
    Invalid,    // 226
    Invalid,    // 227
    Invalid,    // 228
    Invalid,    // 229
    Invalid,    // 230
    Invalid,    // 231
    Invalid,    // 232
    Invalid,    // 233
    Invalid,    // 234
    Invalid,    // 235
    Invalid,    // 236
    Invalid,    // 237
    Invalid,    // 238
    Invalid,    // 239
    Invalid,    // 240
    Invalid,    // 241
    Invalid,    // 242
    Invalid,    // 243
    Invalid,    // 244
    Invalid,    // 245
    Invalid,    // 246
    Invalid,    // 247
    Invalid,    // 248
    Invalid,    // 249
    Invalid,    // 250
    Invalid,    // 251
    Invalid,    // 252
    Invalid,    // 253
    Invalid,    // 254
    Invalid,    // 255
];

#[test]
fn test_gen() {
    for i in 0..=255u8 {
        if i == b'=' {
            print!("Pad, // {i} (=)");
        } else {
            match crate::bytes_ext::BASE64_ENCODE_TABLE
                .iter()
                .position(|&c| c == i)
            {
                Some(idx) => {
                    print!("Sextet({idx}), // {i} ({})", i as char);
                }
                None => {
                    print!("Invalid, // {i}");
                }
            }
        }
        println!();
    }
}
