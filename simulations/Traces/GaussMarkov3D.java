/*******************************************************************************
 ** BonnMotion - a mobility scenario generation and analysis tool             **
 ** Copyright (C) 2002-2012 University of Bonn                                **
 ** Copyright (C) 2012-2020 University of Osnabrueck                          **
 **                                                                           **
 ** 3D extension by: [Your Name / Institution]                                **
 **                                                                           **
 ** Mathematical basis:                                                       **
 **   [1] B. Liang and Z. J. Haas, "Predictive distance-based mobility        **
 **       management for PCS networks," IEEE INFOCOM, 1999.                   **
 **   [2] T. Camp, J. Boleng, V. Davies, "A survey of mobility models for     **
 **       ad hoc network research," Wireless Comm. and Mobile Computing,      **
 **       vol. 2, no. 5, pp. 483-502, 2002.                                   **
 **   [3] Y. Wan et al., "A smooth-turn mobility model for airborne           **
 **       networks," IEEE Trans. Veh. Technol., vol. 62, no. 7, 2013.         **
 **   [4] E. Kuiper and S. Nadjm-Tehrani, "Mobility models for UAV group      **
 **       coordination," ICAS/ICNS, 2006.                                     **
 **                                                                           **
 ** This program is free software; you can redistribute it and/or modify      **
 ** it under the terms of the GNU General Public License as published by      **
 ** the Free Software Foundation; either version 2 of the License, or         **
 ** (at your option) any later version.                                       **
 *******************************************************************************/

package edu.bonn.cs.iv.bonnmotion.models;

import java.io.FileNotFoundException;
import java.io.IOException;

import edu.bonn.cs.iv.bonnmotion.MobileNode;
import edu.bonn.cs.iv.bonnmotion.ModuleInfo;
import edu.bonn.cs.iv.bonnmotion.Position;
import edu.bonn.cs.iv.bonnmotion.Scenario;
import edu.bonn.cs.iv.bonnmotion.ScenarioLinkException;
import edu.bonn.cs.iv.bonnmotion.Waypoint;

/**
 * 3D Gauss-Markov mobility model for BonnMotion.
 *
 * <h3>Design</h3>
 * <p>The 2D GM direction angle is extended to spherical coordinates:
 * <ul>
 *   <li><b>Azimuth θ</b> in [0, 2pi) — horizontal, same Gaussian update as 2D.</li>
 *   <li><b>Elevation phi</b> in (-pi/2, pi/2) — vertical tilt, independent Gaussian update.</li>
 * </ul>
 * Velocity decomposition:
 * <pre>
 *   vx = speed * cos(phi) * cos(theta)
 *   vy = speed * cos(phi) * sin(theta)     |v| = speed always
 *   vz = speed * sin(phi)
 * </pre>
 *
 * <h3>Boundary handling — zone restoration, not bouncing</h3>
 * <p>When a node leaves the volume the mean of the next Gaussian draw is biased
 * toward the interior. XY mirrors existing BonnMotion !checkBounds logic.
 * Z adds an identical correction on the elevation angle.
 *
 * <h3>Critical: parameterData.z is the Z extent</h3>
 * <p>This class uses {@code parameterData.z} as the Z-axis ceiling, parallel to
 * how {@code parameterData.x/y} bound XY. This is required so that
 * {@code setCalculationDimension3D()} sees a non-zero Z dimension. A separate
 * {@code maxZ} field that is never written into {@code parameterData} would leave
 * {@code parameterData.z = 0}, making the framework treat the scenario as 2D and
 * breaking the Z bounds check (which would then compare against 0, not the user's value).
 *
 * <h3>Note on MobileNode.shiftPos</h3>
 * <p>If your MobileNode only has {@code shiftPos(dx, dy)}, add the 3-arg overload:
 * <pre>
 *   public void shiftPos(double dx, double dy, double dz) {
 *       for (Waypoint w : waypoints)
 *           w.pos = new Position(w.pos.x+dx, w.pos.y+dy, w.pos.z+dz);
 *   }
 * </pre>
 */
public class GaussMarkov3D extends Scenario {

    private static ModuleInfo info;

    static {
        info = new ModuleInfo("GaussMarkov3D");
        info.description = "3D Gauss-Markov mobility model with zone restoration";
        info.major    = 1;
        info.minor    = 0;
        info.revision = ModuleInfo.getSVNRevisionStringValue("$LastChangedRevision: 1 $");
        info.contacts.add(ModuleInfo.BM_MAILINGLIST);
        info.authors.add("Extended from University of Bonn GaussMarkov");
        info.affiliation = ModuleInfo.UNIVERSITY_OF_BONN;
    }

    public static ModuleInfo getInfo() { return info; }

    private static final double TWO_PI       = 2.0 * Math.PI;
    private static final double HALF_PI      = 0.5 * Math.PI;
    // 0.99*pi/2: prevents cos(phi) from collapsing to 0 at the poles
    private static final double MAX_ELEVATION = HALF_PI * 0.99;

    // -----------------------------------------------------------------------
    // Parameters.
    // NOTE: There is intentionally NO separate 'maxZ' field.
    //       parameterData.z IS the Z extent. A separate field risks getting
    //       out of sync with parameterData.z and leaving the framework's view
    //       of Z extent at 0.
    // -----------------------------------------------------------------------
    protected double  updateFrequency  = 2.5;
    protected double  maxspeed         = 1.5;
    protected double  minspeed         = 0.0;
    protected double  angleStdDev      = 0.125 * Math.PI;
    protected double  elevationStdDev  = 0.125 * Math.PI;
    protected double  speedStdDev      = 0.5;
    /**
     * Maximum vertical climb or descent rate [m/s].
     * Dynamically caps phi each step so vz = speed*sin(phi) never exceeds this.
     * Realistic values: DJI Phantom 4 = 6 m/s, Mavic 3 = 8 m/s, racing FPV ~10 m/s.
     * CLI: -c
     */
    protected double  maxClimbRate     = 5.0;
    protected boolean gaussSpeed       = false;
    protected boolean uniformSpeed     = false;

    /** Original user-specified extents, stored so the params file round-trips correctly. */
    protected double inputX = 0, inputY = 0, inputZ = 0;

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    public GaussMarkov3D(String[] args) {
        // Must be called before go() so the framework is configured
        // before generate() runs.
        setCalculationDimension3D();
        setOutputDimension3D();
        go(args);
    }

    public GaussMarkov3D(String[] args, Scenario _pre, Integer _transitionMode) {
        super(args, _pre, _transitionMode);
        setCalculationDimension3D();
        setOutputDimension3D();
        go(args);
    }

    public void go(String[] args) {
        super.go(args);
        generate();
    }

    // -----------------------------------------------------------------------
    // Argument parsing
    // -----------------------------------------------------------------------

    @Override
    protected boolean parseArg(String key, String value) {
        switch (key) {
            case "updateFrequency": updateFrequency = Double.parseDouble(value); return true;
            case "maxspeed":        maxspeed        = Double.parseDouble(value); return true;
            case "minspeed":        minspeed        = Double.parseDouble(value); return true;
            case "angleStdDev":     angleStdDev     = Double.parseDouble(value); return true;
            case "elevationStdDev": elevationStdDev = Double.parseDouble(value); return true;
            case "speedStdDev":     speedStdDev     = Double.parseDouble(value); return true;
            case "maxClimbRate":    maxClimbRate    = Double.parseDouble(value); return true;
            case "initGauss":       if (value.equals("true")) gaussSpeed   = true; return true;
            case "uniformSpeed":    if (value.equals("true")) uniformSpeed = true; return true;

            // inputX/Y/Z restore the original user-specified extents into
            // parameterData on reload, overriding the post-shift values written
            // by the superclass as "x", "y", "z" — identical to 2D GaussMarkov.
            case "inputX": parameterData.x = Double.parseDouble(value); return true;
            case "inputY": parameterData.y = Double.parseDouble(value); return true;
            case "inputZ": parameterData.z = Double.parseDouble(value); return true;

            // Intercept "x", "y", "z" so they are NOT passed to super.parseArg.
            // The superclass would otherwise overwrite parameterData.z with the
            // post-shift value ("z=236.0") AFTER inputZ has already restored the
            // correct original value ("inputZ=100.0").
            case "x": case "y": case "z": return true;

            default: return super.parseArg(key, value);
        }
    }

    @Override
    protected boolean parseArg(char key, String val) {
        switch (key) {
            case 'a': angleStdDev     = Double.parseDouble(val);               return true;
            case 'c': maxClimbRate    = Double.parseDouble(val);               return true;
            case 'e': elevationStdDev = Double.parseDouble(val);               return true;
            case 'h': maxspeed        = Double.parseDouble(val);               return true;
            case 'm': minspeed        = Math.max(0.0, Double.parseDouble(val)); return true;
            case 'q': updateFrequency = Double.parseDouble(val);               return true;
            case 's': speedStdDev     = Double.parseDouble(val);               return true;
            // -z sets parameterData.z directly — the Z extent used by the framework.
            case 'z': parameterData.z = Double.parseDouble(val);               return true;
            case 'g': gaussSpeed      = true;                                  return true;
            case 'u': uniformSpeed    = true;                                  return true;
            default:  return super.parseArg(key, val);
        }
    }

    // -----------------------------------------------------------------------
    // Generation
    // -----------------------------------------------------------------------

    public void generate() {
        preGeneration();

        if (maxspeed < minspeed) {
            double tmp = minspeed; minspeed = maxspeed; maxspeed = tmp;
        }

        // Bounding box tracking for post-generation origin shift.
        double bMaxX = parameterData.x, bMaxY = parameterData.y, bMaxZ = parameterData.z;
        double bMinX = 0.0,             bMinY = 0.0,             bMinZ = 0.0;

        for (int i = 0; i < parameterData.nodes.length; i++) {
            parameterData.nodes[i] = new MobileNode();
            double t = 0.0;
            Position src;

            if (isTransition) {
                try {
                    Waypoint lastW = transition(predecessorScenario, transitionMode, i);
                    src = lastW.pos;
                    t   = lastW.time;
                } catch (ScenarioLinkException e) {
                    e.printStackTrace();
                    src = randomInitialPosition();
                }
            } else {
                src = randomInitialPosition();
                if (!parameterData.nodes[i].add(0.0, src)) {
                    System.out.println(getInfo().name + ": error adding initial waypoint for node " + i);
                    System.exit(0);
                }
            }

            double theta = randomNextDouble() * TWO_PI;
            double phi   = (randomNextDouble() - 0.5) * Math.PI;
            double speed = randomNextDouble() * (maxspeed - minspeed) + minspeed;
            if (gaussSpeed) speed = getNewSpeed((maxspeed + minspeed) / 2.0);

            while (t < parameterData.duration) {
                double t1 = t + updateFrequency;

                speed = getNewSpeed(speed);
                theta = getNewAzimuth(theta, src);
                phi   = getNewElevation(phi, src, speed);

                if (speed > 0.0) {
                    // Spherical -> Cartesian.
                    // cos(phi) scaling ensures |v| = speed at all elevations.
                    // |v|^2 = s^2*cos^2(phi)*(cos^2(theta)+sin^2(theta)) + s^2*sin^2(phi)
                    //       = s^2*(cos^2(phi)+sin^2(phi)) = s^2
                    double dx = Math.cos(phi) * Math.cos(theta) * updateFrequency * speed;
                    double dy = Math.cos(phi) * Math.sin(theta) * updateFrequency * speed;
                    double dz = Math.sin(phi)                   * updateFrequency * speed;

                    Position dst = new Position(src.x + dx, src.y + dy, src.z + dz);

                    if (dst.x < bMinX) bMinX = dst.x; else if (dst.x > bMaxX) bMaxX = dst.x;
                    if (dst.y < bMinY) bMinY = dst.y; else if (dst.y > bMaxY) bMaxY = dst.y;
                    if (dst.z < bMinZ) bMinZ = dst.z; else if (dst.z > bMaxZ) bMaxZ = dst.z;

                    if (!parameterData.nodes[i].add(t1, dst)) {
                        System.out.println(getInfo().name + ": error adding waypoint for node " + i);
                        System.exit(0);
                    }
                    src = dst;
                }
                t = t1;
            }
        }

        // Save original extents, then update parameterData with shifted extents.
        // parameterData.z gets the real post-shift Z value so "z=..." in the
        // params file is correct and setCalculationDimension3D() works.
        inputX = parameterData.x;
        inputY = parameterData.y;
        inputZ = parameterData.z;

        double shiftX = Math.abs(bMinX);
        double shiftY = Math.abs(bMinY);
        double shiftZ = Math.abs(bMinZ);

        parameterData.x = Math.ceil(bMaxX + shiftX);
        parameterData.y = Math.ceil(bMaxY + shiftY);
        parameterData.z = Math.ceil(bMaxZ + shiftZ);

        for (int i = 0; i < parameterData.nodes.length; i++)
            parameterData.nodes[i].shiftPos(shiftX, shiftY, shiftZ);

        postGeneration();
    }

    // -----------------------------------------------------------------------
    // Direction update
    // -----------------------------------------------------------------------

    /**
     * Next azimuth angle theta ~ N(mean, sigma_theta^2).
     * Mean = current theta inside XY bounds; corrective inward angle outside.
     * Mirrors the existing 2D BonnMotion zone-restoration logic exactly.
     */
    public double getNewAzimuth(double theta, Position pos) {
        double mean = theta;

        boolean outLeft  = pos.x < 0;
        boolean outRight = pos.x > parameterData.x;
        boolean outBelow = pos.y < 0;
        boolean outAbove = pos.y > parameterData.y;

        if (outLeft) {
            if      (outBelow) mean = 0.25 * Math.PI;   // SW -> NE  ( 45 deg)
            else if (outAbove) mean = 1.75 * Math.PI;   // NW -> SE  (315 deg)
            else               mean = 0.0;              // W  -> E   (  0 deg)
        } else if (outRight) {
            if      (outBelow) mean = 0.75 * Math.PI;   // SE -> NW  (135 deg)
            else if (outAbove) mean = 1.25 * Math.PI;   // NE -> SW  (225 deg)
            else               mean = Math.PI;          // E  -> W   (180 deg)
        } else if (outBelow) {
            mean = 0.5 * Math.PI;                       // S  -> N   ( 90 deg)
        } else if (outAbove) {
            mean = 1.5 * Math.PI;                       // N  -> S   (270 deg)
        }

        return randomNextGaussian() * angleStdDev + mean;
    }

    /**
     * Next elevation angle phi ~ N(mean, sigma_phi^2), clamped to a
     * speed-dependent maximum so that vz = speed*sin(phi) never exceeds
     * maxClimbRate regardless of horizontal speed.
     *
     * Dynamic ceiling: phi_max = arcsin(min(1, maxClimbRate / speed))
     *   - At high speed (e.g. 30 m/s, maxClimbRate=5): phi_max ~  9.6 deg
     *   - At low speed  (e.g.  5 m/s, maxClimbRate=5): phi_max ~ 90 deg (full vertical)
     * This naturally produces realistic UAV behaviour: fast-moving nodes
     * barely deviate from horizontal; hovering/slow nodes can climb steeply.
     *
     * The static MAX_ELEVATION cap is still applied as a hard backstop for
     * the speed=0 edge case so cos(phi) never fully collapses to zero.
     *
     * Mean = current phi inside Z bounds; corrective ±pi/2 outside.
     * Uses parameterData.z for ceiling — not a separate field.
     */
    public double getNewElevation(double phi, Position pos, double speed) {
        double mean = phi;

        if      (pos.z < 0)               mean =  HALF_PI;
        else if (pos.z > parameterData.z) mean = -HALF_PI;

        double newPhi = randomNextGaussian() * elevationStdDev + mean;

        // Dynamic phi ceiling: arcsin(maxClimbRate / speed).
        // Math.min(1.0, ...) guards against floating-point > 1 at very low speeds.
        double dynamicMax = (speed > 0.0)
            ? Math.asin(Math.min(1.0, maxClimbRate / speed))
            : MAX_ELEVATION;

        // Use whichever is tighter: physics-based dynamic cap or pole-avoidance cap.
        double effectiveMax = Math.min(dynamicMax, MAX_ELEVATION);
        return Math.max(-effectiveMax, Math.min(effectiveMax, newPhi));
    }

    // -----------------------------------------------------------------------
    // Speed update — unchanged from 2D GaussMarkov
    // -----------------------------------------------------------------------

    public double getNewSpeed(double oldSpeed) {
        double speed = oldSpeed + randomNextGaussian() * speedStdDev;
        if (uniformSpeed) {
            while (speed < minspeed || speed > maxspeed) {
                if (speed < minspeed) speed = minspeed + (minspeed - speed);
                else                  speed = maxspeed - (speed - maxspeed);
            }
        } else {
            if      (speed < minspeed) speed = minspeed;
            else if (speed > maxspeed) speed = maxspeed;
        }
        return speed;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private Position randomInitialPosition() {
        return new Position(
            parameterData.x * randomNextDouble(),
            parameterData.y * randomNextDouble(),
            parameterData.z * randomNextDouble()
        );
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    @Override
    public void write(String _name) throws FileNotFoundException, IOException {
        String[] p = {
            "updateFrequency="  + updateFrequency,
            "maxspeed="         + maxspeed,
            "minspeed="         + minspeed,
            "angleStdDev="      + angleStdDev,
            "elevationStdDev="  + elevationStdDev,
            "speedStdDev="      + speedStdDev,
            "maxClimbRate="     + maxClimbRate,
            "inputX="           + inputX,
            "inputY="           + inputY,
            "inputZ="           + inputZ,
            "initGauss="        + gaussSpeed,
            "uniformSpeed="     + uniformSpeed
        };
        super.writeParametersAndMovement(_name, p);
    }

    public static void printHelp() {
        System.out.println(getInfo().toDetailString());
        Scenario.printHelp();
        System.out.println(getInfo().name + ":");
        System.out.println("\t-a <azimuth std dev [rad]>        (default pi/8 ~ 0.393)");
        System.out.println("\t-c <max climb/descent rate [m/s]>  (default 5.0; Phantom4=6, Mavic3=8, FPV~10)");
        System.out.println("\t-e <elevation std dev [rad]>      (default pi/8; reduce for flatter motion)");
        System.out.println("\t-h <max speed [m/s]>");
        System.out.println("\t-m <min speed [m/s]>              (default 0)");
        System.out.println("\t-q <update frequency [s]>         (default 2.5)");
        System.out.println("\t-s <speed std dev [m/s]>          (default 0.5)");
        System.out.println("\t-z <simulation volume height [m]>  sets parameterData.z");
        System.out.println("\t-g Gaussian initial speed distribution");
        System.out.println("\t-u force uniform speed distribution");
    }
}