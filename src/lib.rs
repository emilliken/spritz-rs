// spritz encryption in rust.
//
// https://people.csail.mit.edu/rivest/pubs/RS14.pdf
// NOTE: N must be a power of two because you += 2 on w and you xor instead of add/sub.

const N: usize = 256;

pub struct Spritz {
	S: [u8; 256],
	i: u8,
	j: u8,
	k: u8,
	z: u8,
	a: u8,
	w: u8,
}

impl Spritz {
	pub fn new(key: &[u8]) -> Spritz {
		let mut sp = Spritz::initialize_state();
		sp.absorb(key);
		sp
	}

	pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
		assert!(dst.len() == src.len());
		for (i, v) in src.iter().enumerate() {
			dst[i] = v ^ self.drip();
		}
	}

	pub fn hash256(msg: &[u8]) -> Vec<u8> {
		let mut sp = Spritz::initialize_state();
		sp.absorb(msg);
		sp.absorb_stop();
		sp.absorb(&[32]);
		return sp.squeeze(32);
	}

	fn initialize_state() -> Spritz {
		let mut sp = Spritz {
    		S: [0; 256],
			i: 0,
			j: 0,
			k: 0,
			z: 0,
			a: 0,
			w: 1,
		};
		for (i, v) in sp.S.iter_mut().enumerate() {
			*v = i as u8;
		};
		sp
	}

	fn absorb(&mut self, I: &[u8]) {
		for b in I {
			self.absorb_byte(*b);
		}
	}

	fn absorb_byte(&mut self, b: u8) {
		self.absorb_nibble(b & 0xf);
		self.absorb_nibble(b >> 4);
	}

	fn absorb_nibble(&mut self, x: u8) {
		if self.a == (N / 2) as u8 {
			self.shuffle();
		}
		self.S.swap(self.a as usize, (x.wrapping_add((N / 2) as u8)) as usize);
		self.a = self.a.wrapping_add(1);
	}

	fn absorb_stop(&mut self) {
		if self.a == (N / 2) as u8 {
			self.shuffle();
		}
		self.a = self.a.wrapping_add(1);
	}

	fn shuffle(&mut self) {
		self.whip(2 * N);
		self.crush();
		self.whip(2 * N);
		self.crush();
		self.whip(2 * N);
		self.a = 0;
	}

	fn whip(&mut self, r: usize) {
		for _ in 0 .. r {
			self.update();
		}
		// we can do this since N is a power of two.
		self.w = self.w.wrapping_add(2);
	}

	fn crush(&mut self) {
		for v in 0 .. (N / 2) as u8 {
			let idx = ((N - 1) as u8).wrapping_sub(v);
			if self.S[v as usize] > self.S[idx as usize] {
				self.S.swap(v as usize, idx as usize);
			}
		}
	}

	fn squeeze(&mut self, r: usize) -> Vec<u8> {
		if self.a > 0 {
			self.shuffle();
		}
		let mut p = Vec::with_capacity(r);
		for _ in 0 .. r {
			p.push(self.drip())
		}
		return p;
	}

	pub fn drip(&mut self) -> u8 {
		if self.a > 0 {
			self.shuffle();
		}
		self.update();
		return self.output();
	}

	fn output(&mut self) -> u8 {
		let t0 = self.S[(self.z.wrapping_add(self.k)) as usize];
		let t1 = self.S[(self.i.wrapping_add(t0)) as usize];
		self.z = self.S[(self.j.wrapping_add(t1)) as usize];
		return self.z;
	}

	fn update(&mut self) {
		self.i = self.i.wrapping_add(self.w);
		let idx = self.j.wrapping_add(self.S[self.i as usize]);
		self.j = self.k.wrapping_add(self.S[idx as usize]);
		self.k = self.i.wrapping_add(self.k).wrapping_add(self.S[self.j as usize]);
		self.S.swap(self.i as usize, self.j as usize);
	}

}

#[test]
fn it_works() {
	let mut sp = Spritz::new(b"ABC");
	let v = vec![0x77, 0x9a, 0x8e, 0x01, 0xf9, 0xe9, 0xcb, 0xc0];
	let mut res = vec![];
	for _ in &v {
		res.push(sp.drip());
	}
	assert_eq!(res, v);

	let mut sp = Spritz::new(b"spam");
	let v = vec![0xf0, 0x60, 0x9a, 0x1d, 0xf1, 0x43, 0xce, 0xbf];
	let mut res = vec![];
	for _ in &v {
		res.push(sp.drip());
	}
	assert_eq!(res, v);

	let mut sp = Spritz::new(b"arcfour");
	let v = vec![0x1a, 0xfa, 0x8b, 0x5e, 0xe3, 0x37, 0xdb, 0xc7];
	let mut res = vec![];
	for _ in &v {
		res.push(sp.drip());
	}
	assert_eq!(res, v);

	// hashing test vectors

	let h = Spritz::hash256(b"ABC");
	let v = vec![0x02, 0x8f, 0xa2, 0xb4, 0x8b, 0x93, 0x4a, 0x18];
	assert_eq!(&h[..8], &v[..]);

	let h = Spritz::hash256(b"spam");
	let v = vec![0xac, 0xbb, 0xa0, 0x81, 0x3f, 0x30, 0x0d, 0x3a];
	assert_eq!(&h[..8], &v[..]);

	let h = Spritz::hash256(b"arcfour");
	let v = vec![0xff, 0x8c, 0xf2, 0x68, 0x09, 0x4c, 0x87, 0xb9];
	assert_eq!(&h[..8], &v[..]);
}
