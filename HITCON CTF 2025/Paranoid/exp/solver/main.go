package main

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

func getMemoryMB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Alloc) / 1024.0 / 1024.0
}

func defaultGenerator(n *big.Int, index int) *big.Int {
	i, err := rand.Int(rand.Reader, n)
	if err != nil {
		log.Fatalf("Failed to generate random number: %v", err)
	}
	return i
}

// Ancestor tracks the parent lists and the indices within them
// that were used to create a child list's elements.
type Ancestor struct {
	IndexMap [][]int // Maps child index to [left_parent_idx, right_parent_idx]
	Parents  []*List
}

// List represents a list of numbers, which can be a leaf list generated
// from random data or an internal node list created by merging two parent lists.
type List struct {
	Ctx      *SolvingContext
	height   int
	ancestor *Ancestor
	items    []*big.Int
	// onDisk is true if _items has been offloaded to a file.
	onDisk bool
	// diskFilepathItems is the path to the file where items are stored.
	diskFilepathItems    string
	diskFilepathIndexMap string
}

// SolvingContext holds all the configuration and parameters for a solving session.
type SolvingContext struct {
	N             *big.Int
	DesiredSum    *big.Int
	TreeHeight    int
	Generator     func(n *big.Int, i int) *big.Int
	OffloadHeight int
	DiskListDir   string
	ListLength    int
	K             int
	FilterRanges  [][]*big.Int // Slice of [a, b] pairs for each height
}

const indexSize = 4 // we assume that index always fits in 4 bytes

// NewSolvingContext creates and initializes a context for the problem.
func NewSolvingContext(n *big.Int, desiredSum *big.Int, treeHeight int, generator func(n *big.Int, i int) *big.Int) (*SolvingContext, error) {
	if desiredSum.Cmp(n) >= 0 {
		return nil, fmt.Errorf("desired sum (%s) is greater than or equal to modulus (%s)", desiredSum.String(), n.String())
	}

	// Calculate listLength = 2 ** round(log2(n) / (1 + treeHeight))
	bitLength := float64(n.BitLen())
	denom := float64(1 + treeHeight)
	exponent := math.Round(bitLength / denom)
	listLength := int(math.Pow(2, exponent))

	k := 1 << treeHeight // 2**treeHeight

	ctx := &SolvingContext{
		N:             n,
		DesiredSum:    desiredSum,
		TreeHeight:    treeHeight,
		Generator:     generator,
		OffloadHeight: 8, // Default offload height
		DiskListDir:   "./disk_lists",
		ListLength:    listLength,
		K:             k,
	}

	// Pre-calculate filter ranges for each height.
	ctx.FilterRanges = make([][]*big.Int, treeHeight+2)
	for h := 1; h <= treeHeight; h++ {
		// Corresponds to Python's filter_range(h)
		if h == treeHeight {
			ctx.FilterRanges[h] = []*big.Int{new(big.Int).Set(n), big.NewInt(0)}
		} else {
			// divisor = 2 * (list_length**h)
			listLengthH := new(big.Int).Exp(big.NewInt(int64(listLength)), big.NewInt(int64(h)), nil)
			divisor := new(big.Int).Mul(big.NewInt(2), listLengthH)

			// base = n // divisor
			base := new(big.Int).Div(n, divisor)

			// a = n - base
			a := new(big.Int).Sub(n, base)
			// b = base - 1
			b := new(big.Int).Sub(base, big.NewInt(1))
			ctx.FilterRanges[h] = []*big.Int{a, b}
		}
	}

	// Create the directory for offloading lists if it doesn't exist.
	if err := os.MkdirAll(ctx.DiskListDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create disk list directory: %w", err)
	}

	return ctx, nil
}

// generate creates a new leaf list (height 0).
func (ctx *SolvingContext) generate(index int) *List {
	items := make([]*big.Int, ctx.ListLength)
	for i := 0; i < ctx.ListLength; i++ {
		items[i] = ctx.Generator(ctx.N, index)
	}

	l := &List{
		Ctx:    ctx,
		height: 0,
	}

	// If this is the last list (k-1), adjust its elements to target the desired sum.
	if index+1 == ctx.K && ctx.DesiredSum.Cmp(big.NewInt(0)) != 0 {
		originalItems := make([]*big.Int, len(items))
		newItems := make([]*big.Int, len(items))
		indexMap := make([][]int, len(items))

		for i, x := range items {
			originalItems[i] = new(big.Int).Set(x)
			// new_item = (x - desired_sum) % n
			adjusted := new(big.Int).Sub(x, ctx.DesiredSum)
			newItems[i] = adjusted.Mod(adjusted, ctx.N)
			indexMap[i] = []int{i} // Trivial mapping for the base case
		}

		// The original generated list is treated as a "pre-ancestor" at height -1
		preAncestorList := &List{Ctx: ctx, items: originalItems, height: -1}
		l.ancestor = &Ancestor{IndexMap: indexMap, Parents: []*List{preAncestorList}}
		l.items = newItems
	} else {
		l.items = items
	}

	// All lists are sorted upon creation or merging.
	// sort.Slice(l.items, func(i, j int) bool {
	// 	return l.items[i].Cmp(l.items[j]) < 0
	// })

	return l
}

// Len returns the number of items in the list.
func (l *List) Len() int {
	// If items are on disk, we can't know the length without loading.
	// This implementation assumes we don't need Len() for offloaded lists,
	// which holds true for the algorithm's flow.
	if l.onDisk {
		return 0
	}
	return len(l.items)
}

// getItems ensures the list's items are in memory, loading from disk if necessary.
func (l *List) getItems() []*big.Int {
	l.loadItems()
	return l.items
}

func (l *List) getIndexMap() [][]int {
	if l.ancestor != nil {
		l.loadIndexMap()
		return l.ancestor.IndexMap
	}
	return nil
}

func (l *List) getParents() []*List {
	if l.ancestor != nil {
		return l.ancestor.Parents
	}
	return nil
}

func (l *List) loadItems() {
	if l.items == nil {
		file, err := os.Open(l.diskFilepathItems)
		if err != nil {
			log.Fatalf("Failed to open offloaded list file %s: %v", l.diskFilepathItems, err)
		}
		defer file.Close()

		decoder := gob.NewDecoder(file)
		var items []*big.Int
		if err := decoder.Decode(&items); err != nil {
			log.Fatalf("Failed to decode offloaded list from %s: %v", l.diskFilepathItems, err)
		}
		l.items = items
	}
}

func (l *List) loadIndexMap() {
	if l.ancestor != nil && l.ancestor.IndexMap == nil {
		file, err := os.Open(l.diskFilepathIndexMap)
		if err != nil {
			log.Fatalf("Failed to open ancestor index map file %s: %v", l.diskFilepathIndexMap, err)
		}
		defer file.Close()
		decoder := gob.NewDecoder(file)
		var indexMap [][]int
		if err := decoder.Decode(&indexMap); err != nil {
			log.Fatalf("Failed to decode ancestor index map from %s: %v", l.diskFilepathItems, err)
		}
		l.ancestor.IndexMap = indexMap
	}
}

// offload writes the list's items to a temporary file and clears them from memory.
func (l *List) offload() {
	l.diskFilepathItems = fmt.Sprintf("%s/list_h%d_%p_items.gob", l.Ctx.DiskListDir, l.height, l)
	l.diskFilepathIndexMap = fmt.Sprintf("%s/list_h%d_%p_imap.gob", l.Ctx.DiskListDir, l.height, l)

	if l.items != nil {
		file, err := os.Create(l.diskFilepathItems)
		if err != nil {
			log.Fatalf("Failed to create offloaded list file %s: %v", l.diskFilepathItems, err)
		}
		defer file.Close()
		encoder := gob.NewEncoder(file)
		if err := encoder.Encode(l.items); err != nil {
			log.Fatalf("Failed to encode offloaded list to %s: %v", l.diskFilepathItems, err)
		}
		l.items = nil
	}
	if l.ancestor != nil && l.ancestor.IndexMap != nil {
		file, err := os.Create(l.diskFilepathIndexMap)
		if err != nil {
			log.Fatalf("Failed to create ancestor index map file %s: %v", l.diskFilepathIndexMap, err)
		}
		defer file.Close()
		encoder := gob.NewEncoder(file)
		if err := encoder.Encode(l.ancestor.IndexMap); err != nil {
			log.Fatalf("Failed to encode ancestor index map to %s: %v", l.diskFilepathItems, err)
		}
		l.ancestor.IndexMap = nil
	}

}

// offloadAncestorsToDisk recursively offloads parent lists to save memory.
func offloadAncestorsToDisk(l *List) {
	parents := l.getParents()
	if l.height <= 0 || parents == nil {
		return
	}
	for _, parent := range parents {
		parent.offload()
		offloadAncestorsToDisk(parent)
	}
}

// merge combines two lists (L1 and L2) to produce a new, taller list.
// This is the Go equivalent of the `__and__` method with binary search.
func merge(L1, L2 *List) *List {
	ctx := L1.Ctx
	n := ctx.N
	nextHeight := L1.height + 1
	a := ctx.FilterRanges[nextHeight][0]
	b := ctx.FilterRanges[nextHeight][1]

	var sums []*big.Int
	var indexMap [][]int

	items1 := L1.getItems()
	items2 := L2.getItems()

	// sort for binary search
	// sort.Slice(items2, func(i, j int) bool {
	// 	return items2[i].Cmp(items2[j]) < 0
	// })

	// sort for binary search and record index permutation
	argsortItems2 := make([]int, len(items2))
	for i := range items2 {
		argsortItems2[i] = i
	}
	sort.Slice(argsortItems2, func(i, j int) bool {
		return items2[argsortItems2[i]].Cmp(items2[argsortItems2[j]]) < 0
	})
	items2IndexMap := make([]int, len(items2)) // map sorted indices to original indices
	sortedItems2 := make([]*big.Int, len(items2))
	for newIndex, oldIndex := range argsortItems2 {
		items2IndexMap[newIndex] = oldIndex
		sortedItems2[newIndex] = items2[oldIndex]
	}
	items2 = sortedItems2

	lOther := len(items2)

	if lOther == 0 || len(items1) == 0 {
		return &List{Ctx: ctx, height: nextHeight, items: []*big.Int{}}
	}

	for i1, e1 := range items1 {
		// Find the range in L2 where (e1 + e2) % n could fall into [a, b].
		// We need to find the smallest e2 such that e1 + e2 >= a.
		// min_e2 = (a - e1) % n
		minE2 := new(big.Int).Sub(a, e1)
		// minE2.Mod(minE2, n)
		if minE2.Sign() < 0 {
			minE2.Add(minE2, n)
		}

		// bisect_left equivalent using sort.Search
		minIndex := sort.Search(lOther, func(i int) bool {
			return items2[i].Cmp(minE2) >= 0
		})

		// Explore to the right from minIndex, wrapping around if necessary.
		for i := 0; i < lOther; i++ {
			idx := (minIndex + i) % lOther
			e2 := items2[idx]

			// z = (e1 + e2) % n
			z := new(big.Int).Add(e1, e2)
			// z.Mod(z, n)
			zn := new(big.Int).Sub(z, n)
			if zn.Sign() >= 0 {
				z = zn
			}

			// if z >= a or z <= b:
			if z.Cmp(a) >= 0 || z.Cmp(b) <= 0 {
				sums = append(sums, z)
				indexMap = append(indexMap, []int{i1, items2IndexMap[idx]})
			} else {
				// The sums are monotonic, so once we leave the valid range, we can stop.
				break
			}
		}
	}

	// Create the new list with its ancestor information.
	// The new list's items are not yet sorted. We sort them and adjust the index map.
	mergedList := &List{
		Ctx:    ctx,
		height: nextHeight,
		ancestor: &Ancestor{
			IndexMap: indexMap,
			Parents:  []*List{L1, L2},
		},
	}

	mergedList.items = sums
	mergedList.ancestor.IndexMap = indexMap

	// Sort the merged list and apply the same sort order to the index map.
	// type sortableItem struct {
	// 	sum      *big.Int
	// 	indexMap []int
	// }

	// sortable := make([]sortableItem, len(sums))
	// for i := range sums {
	// 	sortable[i] = sortableItem{sum: sums[i], indexMap: indexMap[i]}
	// }

	// sort.Slice(sortable, func(i, j int) bool {
	// 	return sortable[i].sum.Cmp(sortable[j].sum) < 0
	// })

	// // Unpack the sorted items back into the list.
	// finalSums := make([]*big.Int, len(sortable))
	// finalIndexMap := make([][]int, len(sortable))
	// for i, s := range sortable {
	// 	finalSums[i] = s.sum
	// 	finalIndexMap[i] = s.indexMap
	// }

	// mergedList.items = finalSums
	// mergedList.ancestor.IndexMap = finalIndexMap

	return mergedList
}

// atHeight recursively builds a list at a given height in the merge tree.
func (ctx *SolvingContext) atHeight(height, index int) *List {
	if height < 1 {
		log.Fatalf("invalid height: %d", height)
	}

	// Determine indices for left and right parent lists.
	rightIndex := index
	leftIndex := index - (1 << (height - 1))

	st := time.Now()
	if height >= 8 {
		log.Printf("h=%d, index=%d: start", height, index)
	}

	var merged *List
	// Loop until a non-empty list is produced. This handles the case
	// where a merge results in zero valid sums, requiring regeneration.
	for {
		var left, right *List
		if height == 1 {
			// left = ctx.generate(leftIndex)
			// right = ctx.generate(rightIndex)

			done := make(chan struct{}, 2)
			go func() {
				left = ctx.generate(leftIndex)
				done <- struct{}{}
			}()
			go func() {
				right = ctx.generate(rightIndex)
				done <- struct{}{}
			}()
			<-done
			<-done
		} else {
			left = ctx.atHeight(height-1, leftIndex)
			right = ctx.atHeight(height-1, rightIndex)

			// done := make(chan struct{}, 2)
			// go func() {
			// 	left = ctx.atHeight(height-1, leftIndex)
			// 	done <- struct{}{}
			// }()
			// go func() {
			// 	right = ctx.atHeight(height-1, rightIndex)
			// 	done <- struct{}{}
			// }()
			// <-done
			// <-done
		}

		merged = merge(left, right)

		if merged.Len() > 0 {
			break
		}
		log.Printf("Empty merge at height %d, index %d. Retrying.", height, index)
	}

	if height >= 8 {
		elapsed := time.Since(st)
		log.Printf("h=%d, index=%d: len=%d returned in %.2f seconds", height, index, merged.Len(), elapsed.Seconds())
	}

	// If less than the offload height, write ancestors to disk to free memory.
	if height <= ctx.OffloadHeight {
		parents := merged.getParents()
		if merged.height <= 0 || parents == nil {
			return merged
		}
		for _, parent := range parents {
			parent.offload()
		}
	}

	return merged
}

// track recursively follows the ancestor chain to find the original leaf values
// that contributed to a specific element in the final list.
func (l *List) track(index int) ([]*big.Int, []int) {
	if l.ancestor == nil {
		// This is a leaf list.
		return []*big.Int{l.getItems()[index]}, []int{index}
	}

	// The index map points to indices in the *unsorted* parent lists.
	// But our merge function sorts, so this is already handled.
	parentIndices := l.getIndexMap()[index]

	parents := l.getParents()
	leftParent := parents[0]
	rightParent := parents[1]

	// leftSolution := leftParent.track(parentIndices[0])
	// rightSolution := rightParent.track(parentIndices[1])

	// use goroutines to track both parents in parallel
	var leftSolution, rightSolution []*big.Int
	var leftIndex, rightIndex []int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		leftSolution, leftIndex = leftParent.track(parentIndices[0])
	}()
	go func() {
		defer wg.Done()
		rightSolution, rightIndex = rightParent.track(parentIndices[1])
	}()
	wg.Wait()

	// var solution []*big.Int
	// solution = append(solution, leftSolution...)
	// solution = append(solution, rightSolution...)
	solution := append(leftSolution, rightSolution...)
	indexList := append(leftIndex, rightIndex...)

	return solution, indexList
}

// solveParallel computes the solution in parallel.
func solveParallel(ctx *SolvingContext, splitAt int, numWorkers int) *List {
	// index := (1 << ctx.TreeHeight) - 1 // (2^height) - 1

	numSplits := 1 << (ctx.TreeHeight - splitAt)
	indices := make([]int, numSplits)
	for i := 0; i < numSplits; i++ {
		indices[i] = (i+1)*(1<<splitAt) - 1
	}

	samephore := make(chan struct{}, numWorkers)
	currentLevelLists := make([]*List, numSplits)
	notify := make(chan struct{}, numSplits)
	for i, idx := range indices {
		go func(index int) {
			samephore <- struct{}{}
			defer func() { <-samephore }()
			list := ctx.atHeight(splitAt, index)
			currentLevelLists[i] = list
			notify <- struct{}{}
		}(idx)
	}

	for i := 0; i < numSplits; i++ {
		<-notify
		prog := float64(i+1) / float64(numSplits) * 100
		log.Printf("List %d/%d completed (%.2f%% done)", i+1, numSplits, prog)
		log.Printf("Current memory usage: %.2f MB", getMemoryMB())
	}

	// The lists might not be in the correct order for merging. We need to sort them by their original index.
	// This is complex because the list struct doesn't store its own index.
	// However, the `indices` slice is in the correct descending order, and the results
	// are pushed as jobs are consumed. For simplicity, we assume they are roughly in order.
	// A more robust solution would be to return a struct { list *List; index int } from workers.
	// For this translation, we'll proceed assuming the order is correct.

	// Sequentially merge the results from the parallel computation.
	currentHeight := splitAt
	for len(currentLevelLists) > 1 {
		log.Printf("Merging lists: height=%d, count=%d", currentHeight, len(currentLevelLists))
		currentHeight++

		var nextLevelLists []*List
		for i := 0; i < len(currentLevelLists); i += 2 {
			left := currentLevelLists[i]
			right := currentLevelLists[i+1]
			merged := merge(left, right)
			nextLevelLists = append(nextLevelLists, merged)
		}
		currentLevelLists = nextLevelLists
	}

	return currentLevelLists[0]
}

func main() {

	// numWorkers := 4
	numWorkers := 8

	// Set parameters: n = 2^128, treeHeight = 11
	// n := new(big.Int)
	// n.Exp(big.NewInt(2), big.NewInt(128), nil)
	n := secp256k1Order

	// treeHeight := 11
	treeHeight := 15
	desiredSum := big.NewInt(0)

	g := NewGeneratorCtx(targetPk, 1<<treeHeight, 1<<18)

	log.Println("Starting generalized birthday problem solver")
	log.Printf("Tree Height = %d", treeHeight)
	log.Printf("Desired Sum = %s", desiredSum.String())

	// Create the solving context
	ctx, err := NewSolvingContext(n, desiredSum, treeHeight, g.Generate)
	if err != nil {
		log.Fatalf("Error creating context: %v", err)
	}

	log.Printf("List length (lambda) = %d", ctx.ListLength)
	log.Printf("Number of lists (k) = %d", ctx.K)

	// Run the parallel solver
	startTime := time.Now()
	// We split the parallel work at height 8, as in the Python example.
	root := solveParallel(ctx, 8, numWorkers)
	log.Printf("Parallel solving completed. Memory usage: %.2f MB", getMemoryMB())

	endTime := time.Now()

	log.Printf("\n--- Solution Found in %.2f seconds ---", endTime.Sub(startTime).Seconds())
	log.Printf("Found %d solutions", root.Len())

	// take one solution from the root list
	solution, indexList := root.track(0)

	endTimeTracking := time.Now()
	log.Printf("--- Full Solution Found in %.2f seconds ---", endTimeTracking.Sub(startTime).Seconds())
	log.Printf("Tracking solution took %.2f seconds", endTimeTracking.Sub(endTime).Seconds())

	// Verification
	sum := new(big.Int)
	log.Println("Solution components:")
	for _, val := range solution {
		sum.Add(sum, val)
	}
	sum.Mod(sum, n)

	log.Printf("\nVerification Sum (mod n): %s", sum.String())
	if sum.Cmp(desiredSum) == 0 {
		log.Println("✅ Success: The sum of the components matches the desired sum.")
	} else {
		log.Println("❌ Failure: The sum does not match the desired sum.")
	}

	solutionFile, err := os.Create("solution.txt")
	if err != nil {
		log.Fatalf("Failed to create solution file: %v", err)
	}
	defer solutionFile.Close()
	for _, val := range solution {
		_, err := fmt.Fprintf(solutionFile, "%s\n", val.Text(16))
		if err != nil {
			log.Fatalf("Failed to write to solution file: %v", err)
		}
	}

	zs := make([]int, len(indexList))
	for index, idx := range indexList {
		z := g.FindZ(index, idx)
		zs[index] = z
	}

	solutionWithZFile, err := os.Create("solution_with_z.txt")
	if err != nil {
		log.Fatalf("Failed to create solution_with_z file: %v", err)
	}
	defer solutionWithZFile.Close()
	for i, val := range solution {
		_, err := fmt.Fprintf(solutionWithZFile, "%s %d\n", val.Text(16), zs[i])
		if err != nil {
			log.Fatalf("Failed to write to solution_with_z file: %v", err)
		}
	}

	log.Println("Solution written to solution.txt and solution_with_z.txt")
	log.Println("All done!")
}

func init() {
	gob.Register(big.Int{})
}
