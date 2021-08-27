/*
 * Copyright (c) 2021, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.oracle.svm.core.genscavenge;

import java.util.concurrent.locks.ReentrantLock;

import org.graalvm.compiler.api.replacements.Fold;
import org.graalvm.word.UnsignedWord;
import org.graalvm.word.WordFactory;

import com.oracle.svm.core.SubstrateGCOptions;
import com.oracle.svm.core.annotate.Uninterruptible;
import com.oracle.svm.core.heap.GCCause;
import com.oracle.svm.core.heap.PhysicalMemory;
import com.oracle.svm.core.heap.ReferenceAccess;
import com.oracle.svm.core.jdk.UninterruptibleUtils;
import com.oracle.svm.core.option.RuntimeOptionValues;
import com.oracle.svm.core.util.TimeUtils;
import com.oracle.svm.core.util.UnsignedUtils;
import com.oracle.svm.core.util.VMError;

/**
 * A port of HotSpot's ParallelGC adaptive size policy for throughput and footprint, but without the
 * pause time goals. The relevant methods in this class have been adapted from classes
 * {@code PSAdaptiveSizePolicy} and its base class {@code AdaptiveSizePolicy}. Method and variable
 * names have been kept mostly the same for comparability.
 */
final class AdaptiveCollectionPolicy implements CollectionPolicy {

    /*
     * Constants that can be made options if desirable. These are -XX options in HotSpot, refer to
     * their descriptions for details. The values are HotSpot defaults unless labeled otherwise.
     *
     * Don't change these values individually without carefully going over their occurrences in
     * HotSpot source code, there are dependencies between them that are not handled in our code.
     */
    static final int INITIAL_SURVIVOR_RATIO = 8;
    static final int ADAPTIVE_SIZE_POLICY_READY_THRESHOLD = 5;
    static final int ADAPTIVE_SIZE_DECREMENT_SCALE_FACTOR = 4;
    static final int ADAPTIVE_SIZE_POLICY_WEIGHT = 10;
    static final int ADAPTIVE_TIME_WEIGHT = 25;
    static final boolean USE_ADAPTIVE_SIZE_POLICY_WITH_SYSTEM_GC = false;
    static final boolean USE_ADAPTIVE_SIZE_DECAY_MAJOR_GC_COST = true;
    static final double ADAPTIVE_SIZE_MAJOR_GC_DECAY_TIME_SCALE = 10;
    static final boolean USE_ADAPTIVE_SIZE_POLICY_FOOTPRINT_GOAL = true;
    static final int THRESHOLD_TOLERANCE = 10;
    static final int SURVIVOR_PADDING = 3;
    static final int INITIAL_TENURING_THRESHOLD = 7;
    static final int PROMOTED_PADDING = 3;
    static final int TENURED_GENERATION_SIZE_SUPPLEMENT_DECAY = 2;
    static final int YOUNG_GENERATION_SIZE_SUPPLEMENT_DECAY = 8;
    static final int MIN_SURVIVOR_RATIO = 3;
    /*
     * Maximum size increment percentages. We reduce them from HotSpot's default of 20 to avoid
     * growing the heap too eagerly.
     */
    static final int TENURED_GENERATION_SIZE_INCREMENT = 10;
    static final int YOUNG_GENERATION_SIZE_INCREMENT = 10;
    /**
     * Ratio of mutator wall-clock time to GC wall-clock time. HotSpot's default is 99, i.e.
     * spending 1% of time in GC. We set it to 11, i.e. ~8%, to prefer a small footprint.
     */
    static final int GC_TIME_RATIO = 11;
    /*
     * Supplements to accelerate the expansion of the heap at startup. We do not use them in favor
     * of a small footprint.
     */
    static final int YOUNG_GENERATION_SIZE_SUPPLEMENT = 0; // HotSpot default: 80
    static final int TENURED_GENERATION_SIZE_SUPPLEMENT = 0; // HotSpot default: 80
    /**
     * Use least square fitting to estimate if increasing heap sizes will significantly improve
     * throughput. This is intended to limit memory usage once throughput cannot be increased much
     * more, for example when the application is heavily multi-threaded and our single-threaded
     * collector cannot reach the throughput goal. We use a reciprocal function with exponential
     * discounting of old data points, unlike HotSpot's AdaptiveSizeThroughPutPolicy option
     * (disabled by default) which uses linear least-square fitting without discounting.
     */
    static final boolean ADAPTIVE_SIZE_USE_COST_ESTIMATORS = true;
    static final int ADAPTIVE_SIZE_POLICY_INITIALIZING_STEPS = ADAPTIVE_SIZE_POLICY_READY_THRESHOLD;
    /** The minimum increase in throughput in percent for expanding a space by 1% of its size. */
    static final double ADAPTIVE_SIZE_ESTIMATOR_MIN_SIZE_THROUGHPUT_TRADEOFF = 1;
    /** The effective number of most recent data points used by estimator (exponential decay). */
    static final int ADAPTIVE_SIZE_COST_ESTIMATORS_HISTORY_LENGTH = ADAPTIVE_TIME_WEIGHT;

    /* Constants derived from other constants. */
    static final double THROUGHPUT_GOAL = 1.0 - 1.0 / (1.0 + GC_TIME_RATIO);
    static final double THRESHOLD_TOLERANCE_PERCENT = 1.0 + THRESHOLD_TOLERANCE / 100.0;

    /* Constants to compute defaults for values which can be set through existing options. */
    /** HotSpot: -XX:MaxHeapSize default without ergonomics. */
    static final UnsignedWord SMALL_HEAP_SIZE = WordFactory.unsigned(96 * 1024 * 1024);
    static final int NEW_RATIO = 2; // HotSpot: -XX:NewRatio
    static final int LARGE_MEMORY_MAX_HEAP_PERCENT = 25; // -XX:MaxRAMPercentage
    static final int SMALL_MEMORY_MAX_HEAP_PERCENT = 50; // -XX:MinRAMPercentage
    static final double INITIAL_HEAP_MEMORY_PERCENT = 1.5625; // -XX:InitialRAMPercentage

    private final Timer minorTimer = new Timer("minor/between minor");
    private final AdaptiveWeightedAverage avgMinorGcCost = new AdaptiveWeightedAverage(ADAPTIVE_TIME_WEIGHT);
    private final AdaptivePaddedAverage avgSurvived = new AdaptivePaddedAverage(ADAPTIVE_SIZE_POLICY_WEIGHT, SURVIVOR_PADDING);
    private final AdaptivePaddedAverage avgPromoted = new AdaptivePaddedAverage(ADAPTIVE_SIZE_POLICY_WEIGHT, PROMOTED_PADDING, true);
    private final ReciprocalLeastSquareFit minorCostEstimator = new ReciprocalLeastSquareFit(ADAPTIVE_SIZE_COST_ESTIMATORS_HISTORY_LENGTH);
    private long minorCount;
    private long latestMinorMutatorIntervalSeconds;
    private boolean youngGenPolicyIsReady;
    private UnsignedWord youngGenSizeIncrementSupplement = WordFactory.unsigned(YOUNG_GENERATION_SIZE_SUPPLEMENT);
    private int tenuringThreshold;
    private UnsignedWord survivorSize;
    private UnsignedWord edenSize;
    private long youngGenChangeForMinorThroughput;

    private final Timer majorTimer = new Timer("major/between major");
    private final AdaptiveWeightedAverage avgMajorGcCost = new AdaptiveWeightedAverage(ADAPTIVE_TIME_WEIGHT);
    private final AdaptiveWeightedAverage avgMajorIntervalSeconds = new AdaptiveWeightedAverage(ADAPTIVE_TIME_WEIGHT);
    private final AdaptiveWeightedAverage avgOldLive = new AdaptiveWeightedAverage(ADAPTIVE_SIZE_POLICY_WEIGHT);
    private final ReciprocalLeastSquareFit majorCostEstimator = new ReciprocalLeastSquareFit(ADAPTIVE_SIZE_COST_ESTIMATORS_HISTORY_LENGTH);
    private long majorCount;
    private UnsignedWord oldGenSizeIncrementSupplement = WordFactory.unsigned(TENURED_GENERATION_SIZE_SUPPLEMENT);
    private long latestMajorMutatorIntervalSeconds;
    private UnsignedWord promoSize;
    private UnsignedWord oldSize;
    private boolean oldSizeExceededInPreviousCollection;
    private long oldGenChangeForMajorThroughput;

    private volatile SizeParameters sizes;
    private final ReentrantLock sizesUpdateLock = new ReentrantLock();

    @Override
    public String getName() {
        return "adaptive";
    }

    @Override
    public void ensureSizeParametersInitialized() {
        if (sizes == null) {
            updateSizeParameters();
        }
    }

    @Uninterruptible(reason = "Called from uninterruptible code.", mayBeInlined = true)
    private void guaranteeSizeParametersInitialized() {
        VMError.guarantee(sizes != null);
    }

    @Override
    public void updateSizeParameters() {
        PhysicalMemory.tryInitialize();

        SizeParameters params = SizeParameters.compute();
        SizeParameters previous = sizes;
        if (previous != null && params.equal(previous)) {
            return; // nothing to do
        }
        sizesUpdateLock.lock();
        try {
            updateSizeParametersLocked(params, previous);
        } finally {
            sizesUpdateLock.unlock();
        }
        guaranteeSizeParametersInitialized(); // sanity
    }

    @Uninterruptible(reason = "Must be atomic with regard to garbage collection.")
    private void updateSizeParametersLocked(SizeParameters params, SizeParameters previous) {
        if (sizes != previous) {
            // Some other thread beat us and we cannot tell if our values or their values are newer,
            // so back off -- any newer values will be applied eventually.
            return;
        }
        sizes = params;

        if (previous == null || (minorCount == 0 && majorCount == 0)) {
            survivorSize = params.initialSurvivorSize;
            edenSize = params.initialEdenSize;
            oldSize = params.initialOldSize();
            promoSize = UnsignedUtils.min(edenSize, oldSize);
            tenuringThreshold = UninterruptibleUtils.Math.clamp(INITIAL_TENURING_THRESHOLD, 1, HeapParameters.getMaxSurvivorSpaces() + 1);
        }

        /*
         * NOTE: heap limits can change when options are updated at runtime or once the physical
         * memory size becomes known. This means that we start off with sizes which can cause higher
         * GC costs initially, and when shrinking the heap, that previously computed values such as
         * GC costs and intervals and survived/promoted objects are likely no longer representative.
         *
         * We assume that such changes happen very early on and values then adapt reasonably quick,
         * but we must still ensure that computations can handle it (for example, no overflows).
         */
        survivorSize = UnsignedUtils.min(survivorSize, params.maxSurvivorSize());
        edenSize = UnsignedUtils.min(edenSize, maxEdenSize());
        oldSize = UnsignedUtils.min(oldSize, sizes.maxOldSize());
    }

    @Override
    public boolean shouldCollectOnAllocation() {
        if (sizes == null) {
            return false; // updateSizeParameters() has never been called
        }
        UnsignedWord edenUsed = HeapImpl.getHeapImpl().getAccounting().getEdenUsedBytes();
        return edenUsed.aboveOrEqual(edenSize);
    }

    @Override
    public boolean shouldCollectCompletely(boolean followingIncrementalCollection) { // should_{attempt_scavenge,full_GC}
        guaranteeSizeParametersInitialized();

        if (followingIncrementalCollection && oldSizeExceededInPreviousCollection) {
            /*
             * We promoted objects to the old generation beyond its current capacity to avoid a
             * promotion failure, but due to the chunked nature of our heap, we should still be
             * within the maximum heap size. Follow up with a full collection during which we either
             * reclaim enough space or expand the old generation.
             */
            return true;
        }

        UnsignedWord youngUsed = HeapImpl.getHeapImpl().getYoungGeneration().getChunkBytes();
        UnsignedWord oldUsed = HeapImpl.getHeapImpl().getOldGeneration().getChunkBytes();

        /*
         * If the remaining free space in the old generation is less than what is expected to be
         * needed by the next collection, do a full collection now.
         */
        UnsignedWord averagePromoted = UnsignedUtils.fromDouble(avgPromoted.getPaddedAverage());
        UnsignedWord promotionEstimate = UnsignedUtils.min(averagePromoted, youngUsed);
        UnsignedWord oldFree = oldSize.subtract(oldUsed);
        return promotionEstimate.aboveThan(oldFree);
    }

    private void updateAverages(UnsignedWord survivedChunkBytes, UnsignedWord survivorOverflowObjectBytes, UnsignedWord promotedObjectBytes) {
        /*
         * Adding the object bytes of overflowed survivor objects does not consider the overhead of
         * partially filled chunks in the many survivor spaces, so it underestimates the necessary
         * survivors capacity. However, this should self-correct as we expand the survivor space and
         * reduce the tenuring age to avoid overflowing survivor objects in the first place.
         */
        avgSurvived.sample(survivedChunkBytes.add(survivorOverflowObjectBytes));

        avgPromoted.sample(promotedObjectBytes);
    }

    private void computeSurvivorSpaceSizeAndThreshold(boolean isSurvivorOverflow, UnsignedWord survivorLimit) {
        if (!youngGenPolicyIsReady) {
            return;
        }

        boolean incrTenuringThreshold = false;
        boolean decrTenuringThreshold = false;
        if (!isSurvivorOverflow) {
            /*
             * We use the tenuring threshold to equalize the cost of major and minor collections.
             *
             * THRESHOLD_TOLERANCE_PERCENT is used to indicate how sensitive the tenuring threshold
             * is to differences in cost between the collection types.
             */
            if (minorGcCost() > majorGcCost() * THRESHOLD_TOLERANCE_PERCENT) {
                decrTenuringThreshold = true;
            } else if (majorGcCost() > minorGcCost() * THRESHOLD_TOLERANCE_PERCENT) {
                incrTenuringThreshold = true;
            }
        } else {
            decrTenuringThreshold = true;
        }

        UnsignedWord targetSize = minSpaceSize(alignUp(UnsignedUtils.fromDouble(avgSurvived.getPaddedAverage())));
        if (targetSize.aboveThan(survivorLimit)) {
            targetSize = survivorLimit;
            decrTenuringThreshold = true;
        }
        survivorSize = targetSize;

        if (decrTenuringThreshold) {
            tenuringThreshold = Math.max(tenuringThreshold - 1, 1);
        } else if (incrTenuringThreshold) {
            tenuringThreshold = Math.min(tenuringThreshold + 1, HeapParameters.getMaxSurvivorSpaces() + 1);
        }
    }

    private void computeEdenSpaceSize() {
        boolean expansionReducesCost = true; // general assumption
        boolean useEstimator = ADAPTIVE_SIZE_USE_COST_ESTIMATORS && youngGenChangeForMinorThroughput > ADAPTIVE_SIZE_POLICY_INITIALIZING_STEPS;
        if (useEstimator) {
            expansionReducesCost = minorCostEstimator.getSlope(UnsignedUtils.toDouble(edenSize)) <= 0;
        }

        UnsignedWord desiredEdenSize = edenSize;
        if (expansionReducesCost && adjustedMutatorCost() < THROUGHPUT_GOAL && gcCost() > 0) {
            // from adjust_eden_for_throughput():
            UnsignedWord edenHeapDelta = edenIncrementWithSupplementAlignedUp(edenSize);
            double scaleByRatio = minorGcCost() / gcCost();
            assert scaleByRatio >= 0 && scaleByRatio <= 1;
            UnsignedWord scaledEdenHeapDelta = UnsignedUtils.fromDouble(scaleByRatio * UnsignedUtils.toDouble(edenHeapDelta));

            expansionReducesCost = !useEstimator || expansionSignificantlyReducesCost(minorCostEstimator, edenSize, scaledEdenHeapDelta);
            if (expansionReducesCost) {
                desiredEdenSize = alignUp(desiredEdenSize.add(scaledEdenHeapDelta));
                desiredEdenSize = UnsignedUtils.max(desiredEdenSize, edenSize);
                youngGenChangeForMinorThroughput++;
            }
            /*
             * If the estimator says expanding by delta does not lead to a significant improvement,
             * shrink so to not get stuck in a supposed optimum and to keep collecting data points.
             */
        }
        if (!expansionReducesCost || (USE_ADAPTIVE_SIZE_POLICY_FOOTPRINT_GOAL && youngGenPolicyIsReady && adjustedMutatorCost() >= THROUGHPUT_GOAL)) {
            UnsignedWord desiredSum = edenSize.add(promoSize);
            desiredEdenSize = adjustEdenForFootprint(edenSize, desiredSum);
        }
        assert isAligned(desiredEdenSize);
        desiredEdenSize = minSpaceSize(desiredEdenSize);

        UnsignedWord edenLimit = maxEdenSize();
        if (desiredEdenSize.aboveThan(edenLimit)) {
            /*
             * If the policy says to get a larger eden but is hitting the limit, don't decrease
             * eden. This can lead to a general drifting down of the eden size. Let the tenuring
             * calculation push more into the old gen.
             */
            desiredEdenSize = UnsignedUtils.max(edenLimit, edenSize);
        }
        edenSize = desiredEdenSize;
    }

    private boolean expansionSignificantlyReducesCost(ReciprocalLeastSquareFit estimator, UnsignedWord size, UnsignedWord delta) {
        double x0 = UnsignedUtils.toDouble(size);
        double x0Throughput = 1 - estimator.estimate(x0);
        if (x0 == 0 || x0Throughput == 0) { // division by zero below
            return true; // when in doubt, assume expanding makes sense
        }
        double x1 = x0 + UnsignedUtils.toDouble(delta);
        double min = (x1 / x0 - 1) * ADAPTIVE_SIZE_ESTIMATOR_MIN_SIZE_THROUGHPUT_TRADEOFF;
        double estimated = (1 - estimator.estimate(x1)) / x0Throughput - 1;
        return (estimated >= min);
    }

    @Uninterruptible(reason = "Called from uninterruptible code.", mayBeInlined = true)
    private UnsignedWord maxEdenSize() {
        return alignDown(sizes.maxYoungSize.subtract(survivorSize.multiply(2)));
    }

    @Fold
    static UnsignedWord minSpaceSize() {
        return HeapParameters.getAlignedHeapChunkSize();
    }

    @Uninterruptible(reason = "Used in uninterruptible code.", mayBeInlined = true)
    static UnsignedWord alignUp(UnsignedWord size) {
        return UnsignedUtils.roundUp(size, minSpaceSize());
    }

    @Uninterruptible(reason = "Used in uninterruptible code.", mayBeInlined = true)
    static UnsignedWord alignDown(UnsignedWord size) {
        return UnsignedUtils.roundDown(size, minSpaceSize());
    }

    @Uninterruptible(reason = "Used in uninterruptible code.", mayBeInlined = true)
    static boolean isAligned(UnsignedWord size) {
        return UnsignedUtils.isAMultiple(size, minSpaceSize());
    }

    @Uninterruptible(reason = "Used in uninterruptible code.", mayBeInlined = true)
    static UnsignedWord minSpaceSize(UnsignedWord size) {
        return UnsignedUtils.max(size, minSpaceSize());
    }

    private static UnsignedWord adjustEdenForFootprint(UnsignedWord curEden, UnsignedWord desiredSum) {
        assert curEden.belowOrEqual(desiredSum);

        UnsignedWord change = edenDecrement(curEden);
        change = scaleDown(change, curEden, desiredSum);

        UnsignedWord reducedSize = curEden.subtract(change);
        assert reducedSize.belowOrEqual(curEden);
        return alignUp(reducedSize);
    }

    private static UnsignedWord scaleDown(UnsignedWord change, UnsignedWord part, UnsignedWord total) {
        assert part.belowOrEqual(total);
        UnsignedWord reducedChange = change;
        if (total.aboveThan(0)) {
            double fraction = UnsignedUtils.toDouble(part) / UnsignedUtils.toDouble(total);
            reducedChange = UnsignedUtils.fromDouble(fraction * UnsignedUtils.toDouble(change));
        }
        assert reducedChange.belowOrEqual(change);
        return reducedChange;
    }

    private static UnsignedWord edenDecrement(UnsignedWord curEden) {
        return spaceIncrement(curEden, WordFactory.unsigned(YOUNG_GENERATION_SIZE_INCREMENT))
                        .unsignedDivide(ADAPTIVE_SIZE_DECREMENT_SCALE_FACTOR);
    }

    private double adjustedMutatorCost() {
        double cost = 1 - decayingGcCost();
        assert cost >= 0;
        return cost;
    }

    private double decayingGcCost() { // decaying_gc_cost and decaying_major_gc_cost
        double decayedMajorGcCost = majorGcCost();
        double avgMajorInterval = avgMajorIntervalSeconds.getAverage();
        if (USE_ADAPTIVE_SIZE_DECAY_MAJOR_GC_COST && ADAPTIVE_SIZE_MAJOR_GC_DECAY_TIME_SCALE > 0 && avgMajorInterval > 0) {
            double secondsSinceMajor = secondsSinceMajorGc();
            if (secondsSinceMajor > 0 && secondsSinceMajor > ADAPTIVE_SIZE_MAJOR_GC_DECAY_TIME_SCALE * avgMajorInterval) {
                double decayed = decayedMajorGcCost * (ADAPTIVE_SIZE_MAJOR_GC_DECAY_TIME_SCALE * avgMajorInterval) / secondsSinceMajor;
                decayedMajorGcCost = Math.min(decayedMajorGcCost, decayed);
            }
        }
        return Math.min(1, decayedMajorGcCost + minorGcCost());
    }

    private double minorGcCost() {
        return Math.max(0, avgMinorGcCost.getAverage());
    }

    private double majorGcCost() {
        return Math.max(0, avgMajorGcCost.getAverage());
    }

    private double gcCost() {
        double cost = Math.min(1, minorGcCost() + majorGcCost());
        assert cost >= 0 : "Both minor and major costs are non-negative";
        return cost;
    }

    private UnsignedWord edenIncrementWithSupplementAlignedUp(UnsignedWord curEden) {
        return alignUp(spaceIncrement(curEden, youngGenSizeIncrementSupplement.add(YOUNG_GENERATION_SIZE_INCREMENT)));
    }

    private static UnsignedWord spaceIncrement(UnsignedWord curSize, UnsignedWord percentChange) { // {eden,promo}_increment
        return curSize.unsignedDivide(100).multiply(percentChange);
    }

    private double secondsSinceMajorGc() { // time_since_major_gc
        majorTimer.close();
        try {
            return TimeUtils.nanosToSecondsDouble(majorTimer.getMeasuredNanos());
        } finally {
            majorTimer.open();
        }
    }

    @Override
    public void onCollectionBegin(boolean completeCollection) { // {major,minor}_collection_begin
        Timer timer = completeCollection ? majorTimer : minorTimer;
        timer.close();
        if (completeCollection) {
            latestMajorMutatorIntervalSeconds = timer.getMeasuredNanos();
        } else {
            latestMinorMutatorIntervalSeconds = timer.getMeasuredNanos();
        }
        timer.reset();
        timer.open(); // measure collection pause
    }

    @Override
    public void onCollectionEnd(boolean completeCollection, GCCause cause) { // {major,minor}_collection_end
        Timer timer = completeCollection ? majorTimer : minorTimer;
        timer.close();

        if (completeCollection) {
            updateCollectionEndAverages(avgMajorGcCost, majorCostEstimator, avgMajorIntervalSeconds,
                            cause, latestMajorMutatorIntervalSeconds, timer.getMeasuredNanos(), promoSize);
            majorCount++;

        } else {
            updateCollectionEndAverages(avgMinorGcCost, minorCostEstimator, null,
                            cause, latestMinorMutatorIntervalSeconds, timer.getMeasuredNanos(), edenSize);
            minorCount++;

            if (minorCount >= ADAPTIVE_SIZE_POLICY_READY_THRESHOLD) {
                youngGenPolicyIsReady = true;
            }
        }

        timer.reset();
        timer.open();

        GCAccounting accounting = GCImpl.getGCImpl().getAccounting();
        UnsignedWord oldLive = accounting.getOldGenerationAfterChunkBytes();
        oldSizeExceededInPreviousCollection = oldLive.aboveThan(oldSize);

        /*
         * Update the averages that survivor space and tenured space sizes are derived from. Note
         * that we use chunk bytes (not object bytes) for the survivors. This is because they are
         * kept in many spaces (one for each age), which potentially results in significant overhead
         * from chunks that may only be partially filled, especially when the heap is small. Using
         * chunk bytes here ensures that the needed survivor capacity is not underestimated.
         */
        UnsignedWord survivedChunkBytes = HeapImpl.getHeapImpl().getYoungGeneration().getSurvivorChunkBytes();
        UnsignedWord survivorOverflowObjectBytes = accounting.getSurvivorOverflowObjectBytes();
        UnsignedWord tenuredObjBytes = accounting.getTenuredObjectBytes(); // includes overflowed
        updateAverages(survivedChunkBytes, survivorOverflowObjectBytes, tenuredObjBytes);

        computeSurvivorSpaceSizeAndThreshold(survivorOverflowObjectBytes.aboveThan(0), sizes.maxSurvivorSize());
        computeEdenSpaceSize();
        if (completeCollection) {
            computeOldGenSpaceSize(oldLive);
        }
        decaySupplementalGrowth(completeCollection);
    }

    private void computeOldGenSpaceSize(UnsignedWord oldLive) { // compute_old_gen_free_space
        avgOldLive.sample(oldLive);

        // NOTE: if maxOldSize shrunk and difference is negative, unsigned conversion results in 0
        UnsignedWord promoLimit = UnsignedUtils.fromDouble(UnsignedUtils.toDouble(sizes.maxOldSize()) - avgOldLive.getAverage());
        promoLimit = alignDown(UnsignedUtils.max(promoSize, promoLimit));

        boolean expansionReducesCost = true; // general assumption
        boolean useEstimator = ADAPTIVE_SIZE_USE_COST_ESTIMATORS && oldGenChangeForMajorThroughput > ADAPTIVE_SIZE_POLICY_INITIALIZING_STEPS;
        if (useEstimator) {
            expansionReducesCost = majorCostEstimator.getSlope(UnsignedUtils.toDouble(promoSize)) <= 0;
        }

        UnsignedWord desiredPromoSize = promoSize;
        if (expansionReducesCost && adjustedMutatorCost() < THROUGHPUT_GOAL && gcCost() > 0) {
            // from adjust_promo_for_throughput():
            UnsignedWord promoHeapDelta = promoIncrementWithSupplementAlignedUp(promoSize);
            double scaleByRatio = majorGcCost() / gcCost();
            assert scaleByRatio >= 0 && scaleByRatio <= 1;
            UnsignedWord scaledPromoHeapDelta = UnsignedUtils.fromDouble(scaleByRatio * UnsignedUtils.toDouble(promoHeapDelta));

            expansionReducesCost = !useEstimator || expansionSignificantlyReducesCost(majorCostEstimator, promoSize, scaledPromoHeapDelta);
            if (expansionReducesCost) {
                desiredPromoSize = alignUp(promoSize.add(scaledPromoHeapDelta));
                desiredPromoSize = UnsignedUtils.max(desiredPromoSize, promoSize);
                oldGenChangeForMajorThroughput++;
            }
            /*
             * If the estimator says expanding by delta does not lead to a significant improvement,
             * shrink so to not get stuck in a supposed optimum and to keep collecting data points.
             */
        }
        if (!expansionReducesCost || (USE_ADAPTIVE_SIZE_POLICY_FOOTPRINT_GOAL && youngGenPolicyIsReady && adjustedMutatorCost() >= THROUGHPUT_GOAL)) {
            UnsignedWord desiredSum = edenSize.add(promoSize);
            desiredPromoSize = adjustPromoForFootprint(promoSize, desiredSum);
        }
        assert isAligned(desiredPromoSize);
        desiredPromoSize = minSpaceSize(desiredPromoSize);

        desiredPromoSize = UnsignedUtils.min(desiredPromoSize, promoLimit);
        promoSize = desiredPromoSize;

        // from PSOldGen::resize
        UnsignedWord desiredFreeSpace = calculatedOldFreeSizeInBytes();
        UnsignedWord desiredOldSize = alignUp(oldLive.add(desiredFreeSpace));
        oldSize = UnsignedUtils.clamp(desiredOldSize, minSpaceSize(), sizes.maxOldSize());
    }

    UnsignedWord calculatedOldFreeSizeInBytes() {
        return UnsignedUtils.fromDouble(UnsignedUtils.toDouble(promoSize) + avgPromoted.getPaddedAverage());
    }

    private static UnsignedWord adjustPromoForFootprint(UnsignedWord curPromo, UnsignedWord desiredSum) {
        assert curPromo.belowOrEqual(desiredSum);

        UnsignedWord change = promoDecrement(curPromo);
        change = scaleDown(change, curPromo, desiredSum);

        UnsignedWord reducedSize = curPromo.subtract(change);
        assert reducedSize.belowOrEqual(curPromo);
        return alignUp(reducedSize);
    }

    private static UnsignedWord promoDecrement(UnsignedWord curPromo) {
        return promoIncrement(curPromo).unsignedDivide(ADAPTIVE_SIZE_DECREMENT_SCALE_FACTOR);
    }

    private static UnsignedWord promoIncrement(UnsignedWord curPromo) {
        return spaceIncrement(curPromo, WordFactory.unsigned(TENURED_GENERATION_SIZE_INCREMENT));
    }

    private UnsignedWord promoIncrementWithSupplementAlignedUp(UnsignedWord curPromo) {
        return alignUp(spaceIncrement(curPromo, oldGenSizeIncrementSupplement.add(TENURED_GENERATION_SIZE_INCREMENT)));
    }

    private void decaySupplementalGrowth(boolean completeCollection) {
        // Decay the supplement growth factor even if it is not used. It is only meant to give a
        // boost to the initial growth and if it is not used, then it was not needed.
        if (completeCollection) {
            // Don't wait for the threshold value for the major collections. If here, the
            // supplemental growth term was used and should decay.
            if (majorCount % TENURED_GENERATION_SIZE_SUPPLEMENT_DECAY == 0) {
                oldGenSizeIncrementSupplement = oldGenSizeIncrementSupplement.unsignedShiftRight(1);
            }
        } else {
            if (minorCount >= ADAPTIVE_SIZE_POLICY_READY_THRESHOLD && minorCount % YOUNG_GENERATION_SIZE_SUPPLEMENT_DECAY == 0) {
                youngGenSizeIncrementSupplement = youngGenSizeIncrementSupplement.unsignedShiftRight(1);
            }
        }
    }

    private static void updateCollectionEndAverages(AdaptiveWeightedAverage costAverage, ReciprocalLeastSquareFit costEstimator,
                    AdaptiveWeightedAverage intervalSeconds, GCCause cause, long mutatorNanos, long pauseNanos, UnsignedWord sizeBytes) {
        if (cause == GenScavengeGCCause.OnAllocation || USE_ADAPTIVE_SIZE_POLICY_WITH_SYSTEM_GC) {
            double cost = 0;
            double mutatorInSeconds = TimeUtils.nanosToSecondsDouble(mutatorNanos);
            double pauseInSeconds = TimeUtils.nanosToSecondsDouble(pauseNanos);
            if (mutatorInSeconds > 0 && pauseInSeconds > 0) {
                double intervalInSeconds = mutatorInSeconds + pauseInSeconds;
                cost = pauseInSeconds / intervalInSeconds;
                costAverage.sample((float) cost);
                if (intervalSeconds != null) {
                    intervalSeconds.sample((float) intervalInSeconds);
                }
            }
            costEstimator.sample(UnsignedUtils.toDouble(sizeBytes), cost);
        }
    }

    @Override
    public UnsignedWord getMaximumHeapSize() {
        guaranteeSizeParametersInitialized();
        return sizes.maxHeapSize;
    }

    @Override
    public UnsignedWord getMaximumYoungGenerationSize() {
        guaranteeSizeParametersInitialized();
        return sizes.maxYoungSize;
    }

    @Override
    public UnsignedWord getCurrentHeapCapacity() {
        guaranteeSizeParametersInitialized();
        return edenSize.add(survivorSize.multiply(2)).add(oldSize);
    }

    @Override
    public UnsignedWord getSurvivorSpacesCapacity() {
        guaranteeSizeParametersInitialized();
        return survivorSize;
    }

    @Override
    public UnsignedWord getMaximumFreeReservedSize() {
        guaranteeSizeParametersInitialized();
        /*
         * Keep chunks ready for allocations in eden and for the survivor to-spaces during young
         * collections (although we might keep too many aligned chunks when large objects in
         * unallocated chunks are also allocated). We could alternatively return
         * getCurrentHeapCapacity() to have chunks ready during full GCs as well.
         */
        return edenSize.add(survivorSize);
    }

    @Override
    public int getTenuringAge() {
        return tenuringThreshold;
    }

    @Override
    public UnsignedWord getMinimumHeapSize() {
        return sizes.minHeapSize;
    }

    static final class SizeParameters {
        final UnsignedWord maxHeapSize;
        final UnsignedWord maxYoungSize;
        final UnsignedWord initialHeapSize;
        final UnsignedWord initialEdenSize;
        final UnsignedWord initialSurvivorSize;
        final UnsignedWord minHeapSize;

        static SizeParameters compute() {
            UnsignedWord addressSpaceSize = ReferenceAccess.singleton().getAddressSpaceSize();
            UnsignedWord minAllSpaces = minSpaceSize().multiply(2); // eden, old
            if (HeapParameters.getMaxSurvivorSpaces() > 0) {
                minAllSpaces = minAllSpaces.add(minSpaceSize().multiply(2)); // survivor from and to
            }

            UnsignedWord maxHeap;
            long optionMax = SubstrateGCOptions.MaxHeapSize.getValue();
            if (optionMax > 0L) {
                maxHeap = WordFactory.unsigned(optionMax);
            } else if (!PhysicalMemory.isInitialized()) {
                maxHeap = addressSpaceSize;
            } else {
                UnsignedWord physicalMemorySize = PhysicalMemory.getCachedSize();
                if (HeapParameters.Options.MaximumHeapSizePercent.hasBeenSet(RuntimeOptionValues.singleton())) {
                    maxHeap = physicalMemorySize.unsignedDivide(100).multiply(HeapParameters.getMaximumHeapSizePercent());
                } else {
                    UnsignedWord reasonableMax = physicalMemorySize.unsignedDivide(100).multiply(LARGE_MEMORY_MAX_HEAP_PERCENT);
                    UnsignedWord reasonableMin = physicalMemorySize.unsignedDivide(100).multiply(SMALL_MEMORY_MAX_HEAP_PERCENT);
                    if (reasonableMin.belowThan(SMALL_HEAP_SIZE)) {
                        // small physical memory, use a small fraction for the heap
                        reasonableMax = reasonableMin;
                    } else {
                        reasonableMax = UnsignedUtils.max(reasonableMax, SMALL_HEAP_SIZE);
                    }
                    maxHeap = reasonableMax;
                }
            }
            maxHeap = UnsignedUtils.clamp(alignDown(maxHeap), minAllSpaces, alignDown(addressSpaceSize));

            UnsignedWord maxYoung;
            long optionMaxYoung = SubstrateGCOptions.MaxNewSize.getValue();
            if (optionMaxYoung > 0L) {
                maxYoung = WordFactory.unsigned(optionMaxYoung);
            } else if (HeapParameters.Options.MaximumYoungGenerationSizePercent.hasBeenSet(RuntimeOptionValues.singleton())) {
                maxYoung = maxHeap.unsignedDivide(100).multiply(HeapParameters.getMaximumYoungGenerationSizePercent());
            } else {
                maxYoung = maxHeap.unsignedDivide(NEW_RATIO + 1);
            }
            maxYoung = UnsignedUtils.clamp(alignUp(maxYoung), minSpaceSize(), maxHeap);

            UnsignedWord maxOld = maxHeap.subtract(maxYoung);
            maxOld = minSpaceSize(alignUp(maxOld));
            maxHeap = maxYoung.add(maxOld);
            if (maxHeap.aboveThan(addressSpaceSize)) {
                maxYoung = alignDown(maxYoung.subtract(minSpaceSize()));
                maxHeap = maxYoung.add(maxOld);
                VMError.guarantee(maxHeap.belowOrEqual(addressSpaceSize) && maxYoung.aboveOrEqual(minSpaceSize()));
            }

            UnsignedWord minHeap = WordFactory.zero();
            long optionMin = SubstrateGCOptions.MinHeapSize.getValue();
            if (optionMin > 0L) {
                minHeap = WordFactory.unsigned(optionMin);
            }
            minHeap = UnsignedUtils.clamp(alignUp(minHeap), minAllSpaces, maxHeap);

            UnsignedWord initialHeap;
            if (PhysicalMemory.isInitialized()) {
                initialHeap = UnsignedUtils.fromDouble(UnsignedUtils.toDouble(PhysicalMemory.getCachedSize()) / 100 * INITIAL_HEAP_MEMORY_PERCENT);
            } else {
                initialHeap = SMALL_HEAP_SIZE;
            }
            initialHeap = UnsignedUtils.clamp(alignUp(initialHeap), minHeap, maxHeap);

            UnsignedWord initialYoung;
            if (initialHeap.equal(maxHeap)) {
                initialYoung = maxYoung;
            } else {
                initialYoung = UnsignedUtils.clamp(alignUp(initialHeap.unsignedDivide(NEW_RATIO + 1)), minSpaceSize(), maxYoung);
            }
            UnsignedWord initialSurvivor = WordFactory.zero();
            if (HeapParameters.getMaxSurvivorSpaces() > 0) {
                /*
                 * In HotSpot, this is the reserved capacity of each of the survivor From and To
                 * spaces, i.e., together they occupy 2x this size. Our chunked heap doesn't reserve
                 * memory, so we use never occupy more than 1x this size for survivors except during
                 * collections. However, this is inconsistent with how we interpret the maximum size
                 * of the old generation, which we can exceed the (current) old gen size while
                 * copying during collections.
                 */
                initialSurvivor = minSpaceSize(alignUp(initialYoung.unsignedDivide(INITIAL_SURVIVOR_RATIO)));
            }
            UnsignedWord initialEden = minSpaceSize(alignUp(initialYoung.subtract(initialSurvivor.multiply(2))));

            return new SizeParameters(maxHeap, maxYoung, initialHeap, initialEden, initialSurvivor, minHeap);
        }

        private SizeParameters(UnsignedWord maxHeapSize, UnsignedWord maxYoungSize, UnsignedWord initialHeapSize,
                        UnsignedWord initialEdenSize, UnsignedWord initialSurvivorSize, UnsignedWord minHeapSize) {
            this.maxHeapSize = maxHeapSize;
            this.maxYoungSize = maxYoungSize;
            this.initialHeapSize = initialHeapSize;
            this.initialEdenSize = initialEdenSize;
            this.initialSurvivorSize = initialSurvivorSize;
            this.minHeapSize = minHeapSize;

            assert isAligned(maxHeapSize) && isAligned(maxYoungSize) && isAligned(initialHeapSize) && isAligned(initialEdenSize) && isAligned(initialSurvivorSize);
            assert isAligned(maxSurvivorSize()) && isAligned(initialYoungSize()) && isAligned(initialOldSize()) && isAligned(maxOldSize());

            assert initialHeapSize.belowOrEqual(maxHeapSize);
            assert maxSurvivorSize().belowThan(maxYoungSize);
            assert maxYoungSize.add(maxOldSize()).equal(maxHeapSize);
            assert maxHeapSize.belowOrEqual(ReferenceAccess.singleton().getAddressSpaceSize());
            assert initialEdenSize.add(initialSurvivorSize.multiply(2)).equal(initialYoungSize());
            assert initialYoungSize().add(initialOldSize()).equal(initialHeapSize);
        }

        @Uninterruptible(reason = "Called from uninterruptible code.", mayBeInlined = true)
        UnsignedWord maxSurvivorSize() {
            if (HeapParameters.getMaxSurvivorSpaces() == 0) {
                return WordFactory.zero();
            }
            UnsignedWord size = maxYoungSize.unsignedDivide(MIN_SURVIVOR_RATIO);
            return minSpaceSize(alignDown(size));
        }

        @Uninterruptible(reason = "Called from uninterruptible code.", mayBeInlined = true)
        UnsignedWord initialYoungSize() {
            return initialEdenSize.add(initialSurvivorSize.multiply(2));
        }

        @Uninterruptible(reason = "Called from uninterruptible code.", mayBeInlined = true)
        UnsignedWord initialOldSize() {
            return initialHeapSize.subtract(initialYoungSize());
        }

        @Uninterruptible(reason = "Called from uninterruptible code.", mayBeInlined = true)
        UnsignedWord maxOldSize() {
            return maxHeapSize.subtract(maxYoungSize);
        }

        @Uninterruptible(reason = "Called from uninterruptible code.", mayBeInlined = true)
        boolean equal(SizeParameters other) {
            return maxHeapSize.equal(other.maxHeapSize) && maxYoungSize.equal(other.maxYoungSize) && initialHeapSize.equal(other.initialHeapSize) &&
                            initialEdenSize.equal(other.initialEdenSize) && initialSurvivorSize.equal(other.initialSurvivorSize) && minHeapSize.equal(other.minHeapSize);
        }
    }
}
