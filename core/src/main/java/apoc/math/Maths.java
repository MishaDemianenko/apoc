package apoc.math;

import org.neo4j.procedure.Description;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.UserFunction;

/**
 * @author mh
 * @since 12.12.16
 */
public class Maths {

    @UserFunction
    @Description("apoc.math.maxLong() | return the maximum value a long can have")
    public Long maxLong(){
        return Long.MAX_VALUE;
    }

    @UserFunction
    @Description("apoc.math.minLong() | return the minimum value a long can have")
    public Long minLong(){
        return Long.MIN_VALUE;
    }

    @UserFunction
    @Description("apoc.math.maxDouble() | return the largest positive finite value of type double")
    public Double maxDouble(){
        return Double.MAX_VALUE;
    }

    @UserFunction
    @Description("apoc.math.minDouble() | return the smallest positive nonzero value of type double")
    public Double minDouble(){
        return Double.MIN_VALUE;
    }

    @UserFunction
    @Description("apoc.math.maxInt() | return the maximum value an int can have")
    public Long maxInt(){
        return Long.valueOf(Integer.MAX_VALUE);
    }

    @UserFunction
    @Description("apoc.math.minInt() | return the minimum value an int can have")
    public Long minInt(){
        return Long.valueOf(Integer.MIN_VALUE);
    }

    @UserFunction
    @Description("apoc.math.maxByte() | return the maximum value an byte can have")
    public Long maxByte(){
        return Long.valueOf(Byte.MAX_VALUE);
    }

    @UserFunction
    @Description("apoc.math.minByte() | return the minimum value an byte can have")
    public Long minByte(){
        return Long.valueOf(Byte.MIN_VALUE);
    }

    @UserFunction
    @Description("apoc.math.sigmoid(val) | returns the sigmoid value")
    public Double sigmoid(@Name("value") Double value) {
        if (value == null) return null;
        return 1.0 / (1.0 + Math.exp(-value));
    }

    @UserFunction
    @Description("apoc.math.sigmoidPrime(val) | returns the sigmoid prime [ sigmoid(val) * (1 - sigmoid(val)) ]")
    public Double sigmoidPrime(@Name("value") Double value) {
        if (value == null) return null;
        return sigmoid(value) * (1 - sigmoid(value));
    }

    @UserFunction
    @Description("apoc.math.tanh(val) | returns the hyperbolic tangent")
    public Double tanh(@Name("value") Double value) {
        if (value == null) return null;
        return sinh(value) / cosh(value);
    }

    @UserFunction
    @Description("apoc.math.coth(val) | returns the hyperbolic cotangent")
    public Double coth(@Name("value") Double value) {
        if (value == null || value.equals(0D)) return null;
        return cosh(value) / sinh(value);
    }

    @UserFunction
    @Description("apoc.math.cosh(val) | returns the hyperbolic cosin")
    public Double cosh(@Name("value") Double value) {
        if (value == null) return null;
        return (Math.exp(value) + Math.exp(-value)) / 2;
    }

    @UserFunction
    @Description("apoc.math.sinh(val) | returns the hyperbolic sin")
    public Double sinh(@Name("value") Double value) {
        if (value == null) return null;
        return (Math.exp(value) - Math.exp(-value)) / 2;
    }

    @UserFunction
    @Description("apoc.math.sech(val) | returns the hyperbolic secant")
    public Double sech(@Name("value") Double value) {
        if (value == null) return null;
        return 1 / cosh(value);
    }

    @UserFunction
    @Description("apoc.math.csch(val) | returns the hyperbolic cosecant")
    public Double csch(@Name("value") Double value) {
        if (value == null || value.equals(0D)) return null;
        return 1 / sinh(value);
    }

}
