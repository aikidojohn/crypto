package com.johnhite.crypto.schnorr;

import java.math.BigInteger;
import java.util.Objects;

public abstract class AbstractCurvePt implements CurvePt {
    protected final ECCoordinateSystem coordinateSystem;
    protected final BigInteger x;
    protected final BigInteger z;
    protected BigInteger y;

    protected final EllipticCurve curve;


    public AbstractCurvePt(EllipticCurve curve, ECCoordinateSystem coordinateSystem, BigInteger x, BigInteger y, BigInteger z) {
        this.curve = curve;
        this.coordinateSystem = coordinateSystem;
        this.x = x;
        this.y = y;
        this.z = z;
    }
    @Override
    public ECCoordinateSystem getCoordinateSystem() {
        return coordinateSystem;
    }

    @Override
    public BigInteger getX() {
        return x;
    }

    @Override
    public BigInteger getY() {
        if (y == null) {
            y = curve.y(x);
        }
        return y;
    }

    @Override
    public BigInteger getZ() {
        return z;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractCurvePt that = (AbstractCurvePt) o;
        return coordinateSystem == that.coordinateSystem && x.equals(that.x) && z.equals(that.z) && Objects.equals(y, that.y) && curve.equals(that.curve);
    }

    @Override
    public int hashCode() {
        return Objects.hash(coordinateSystem, x, z, y, curve);
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("CurvePt{");
        sb.append("x=").append(x);
        if (y != null) {
            sb.append(", y=").append(y);
        }
        if (coordinateSystem != ECCoordinateSystem.AFFINE) {
            sb.append(", z=").append(z);
        }
        sb.append('}');
        return sb.toString();
    }
}
