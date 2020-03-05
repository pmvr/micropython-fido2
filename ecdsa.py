from uos import urandom


def xgcd(b, n):
    """extended euclidian algorithm"""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        (q, n), b = divmod(b, n), n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return x0, y0  # ggT(b,n) = x0*b + y0*n


def modinv(b, modulus):
    """calculates b^-1 mod modulus"""
    x0, _ = xgcd(b, modulus)
    if x0 > 0:
        return x0
    else:
        return x0 + modulus  # b^-1


class point:
    """class for point on curve"""
    def __init__(self, x, y, Infinity=False):
        self.Infinity = Infinity
        self.x = x
        self.y = y

    def __eq__(self, Q):
        if self.Infinity and Q.Infinity:
            return True
        elif self.Infinity or Q.Infinity:
            return False
        else:
            return self.x == Q.x and self.y == Q.y

    def __str__(self):
        if self.Infinity:
            return "Infinity"
        else:
            return "(%d, %d)" % (self.x, self.y)

    def __repr__(self):
        if self.Infinity:
            return "Infinity"
        else:
            return "(%d, %d)" % (self.x, self.y)


class curve:
    """class for computations on elliptic curve"""
    Infinity = point(0, 0, True)  # point at infinity

    def __init__(self, p, a, b, Px, Py, m, bytelen_p, bytelen_m):
        """y² = x³ + ax + b  (mod p)

        Keyword arguments:
        Px, Py -- x- and y-coordinate of base point
        m      -- order of base point
        """
        self.p = p
        self.a = a
        self.b = b
        self.P = point(Px, Py)  # base point
        self.m = m              # order of base point
        self.bytelen_p = bytelen_p
        self.bytelen_m = bytelen_m

    def verify_point(self, P):
        if P.Infinity is True:
            return True
        else:
            return (P.y**2 - pow(P.x, 3, self.p) - self.a * P.x - self.b) % self.p == 0

    def double(self, x1, y1, z1):
        # jacobian coordinates
        s = (4 * x1 * pow(y1, 2, self.p)) % self.p
        t = pow(y1, 4, self.p)
        m = (3 * pow(x1, 2, self.p) + self.a * pow(z1, 4, self.p)) % self.p
        x3 = (m**2 - 2 * s) % self.p
        y3 = (m * (s - x3) - 8 * t) % self.p
        z3 = (2 * y1 * z1) % self.p
        return x3, y3, z3

    def add(self, x1, y1, z1, x2, y2, z2):
        # jacobian coordinates
        u1 = (x1 * pow(z2, 2, self.p)) % self.p
        u2 = (x2 * pow(z1, 2, self.p)) % self.p
        s1 = (y1 * pow(z2, 3, self.p)) % self.p
        s2 = (y2 * pow(z1, 3, self.p)) % self.p
        if (u1 == u2):
            if (s1 != s2):
                return 0, 0, 0
            else:
                return self.double(x1, x2, z1)
        h = u2 - u1
        r = s2 - s1
        v = (u1 * pow(h, 2, self.p)) % self.p
        g = pow(h, 3, self.p)
        x3 = (pow(r, 2, self.p) - g - 2 * v) % self.p
        y3 = (r * (v - x3) - s1 * g) % self.p
        z3 = (z1 * z2 * h) % self.p
        return x3, y3, z3

    def kP(self, k, P):
        """scalar point multiplication k*P"""
        if k == 0:
            return curve.Infinity
        else:
            zp = int.from_bytes(urandom(self.bytelen_p - 1), 'big', False) | 1
            xp = P.x * pow(zp, 2, self.p) % self.p
            yp = P.y * pow(zp, 3, self.p) % self.p
            while k & 1 == 0:
                xp, yp, zp = self.double(xp, yp, zp)
                k >>= 1
            x, y, z = xp, yp, zp
            k >>= 1
            while k > 0:
                xp, yp, zp = self.double(xp, yp, zp)
                if k & 1 == 1:
                    if z == 0:
                        x, y, z = xp, yp, zp
                    else:
                        x, y, z = self.add(x, y, z, xp, yp, zp)
                k >>= 1

            return self.jacobian2affin(x, y, z)

    def keyGen(self):
        """key generation: Q = d*P, -> (d,Q)"""
        # bias negligible
        d = int.from_bytes(urandom(self.bytelen_p + 5), 'big', False)
        Q = self.kP(d, self.P)
        return (d % self.m, Q)

    def jacobian2affin(self, x, y, z):
        if z % self.p == 0:
            return curve.Infinity
        else:
            zi = modinv(z, self.p)
            zi2 = pow(zi, 2, self.p)
            return point(x * zi2 % self.p, y * zi2 * zi % self.p)


secp256r1 = curve(
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    Px=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    Py=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    m=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    bytelen_p=32, bytelen_m=32)


def ecdsa_sign(curve, sk, h):
    """ ECDSA signature generation

    Keyword arguments:
    curve -- elliptic curve
    sk    -- signing key
    h     -- hash
    """
    while True:
        k, Q = curve.keyGen()
        r = Q.x % curve.m
        rnd = int.from_bytes(urandom(5), 'big', False)
        s = (modinv(k + rnd * curve.m, curve.m) * (h + r * sk)) % curve.m
        if r != 0 and s != 0:
            break

    # sig = 30 len(r)+len(s)+4 02 len(r) r 02 len(s) s
    rb = r.to_bytes(curve.bytelen_m, 'big')
    while rb[0] == 0:
        rb = rb[1:]
    if rb[0] & 0x80 != 0:
        rb = b'\x00' + rb
    sb = s.to_bytes(curve.bytelen_m, 'big')
    while sb[0] == 0:
        sb = sb[1:]
    if sb[0] & 0x80 != 0:
        sb = b'\x00' + sb
    return bytes((0x30,
                  len(rb) + len(sb) + 4, 0x02,
                  len(rb))) + rb + bytes((0x02, len(sb))) + sb
