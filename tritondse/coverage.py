# built-in imports
import os
import json
import logging
import hashlib
import struct

from typing      import List, Generator, Tuple, Set, Union, Dict
from collections import Counter
from enum        import IntEnum

# local imports
from tritondse.workspace import Workspace
from tritondse.types     import Addr, PathConstraint, PathBranch, Solver, PathHash, Edge


CovItem = Union[Addr, Edge, PathHash]
"""
Abstract type representing a coverage item
that can be an address an edge a path etc..
"""


class CoverageStrategy(IntEnum):
    """
    Enum that defines the strategy of coverage
    """
    CODE_COVERAGE = 0
    PATH_COVERAGE = 1
    EDGE_COVERAGE = 2


class BranchCheckStrategy(IntEnum):
    """
    Enum that defines the strategy with which the new path
    enumeration will be performed
    """
    ALL_NOT_COVERED = 0
    FIRST_LAST_NOT_COVERED = 1


class CoverageSingleRun(object):
    """
    This class is used to represent the coverage of an execution.
    """

    def __init__(self, strategy: CoverageStrategy):
        self.strategy = strategy

        # For instruction coverage
        self.instructions = Counter()
        self.not_instructions = set()

        # For edge coverage
        self.edges = Counter()
        self.not_edges = set()

        # For path coverage
        self.paths = set()
        self.not_paths = set()
        self.current_path = []  # Hold all addresses currently forming the path taken
        self.current_path_hash = hashlib.md5()


    def add_covered_address(self, address: Addr):
        """
        Add an instruction address to our covered instructions list.

        :param adresses: The address of the instruction
        :return: None
        """
        self.instructions[address] += 1
        self.not_instructions.discard(address)  # remove address from non-covered if inside


    def add_covered_branch(self, program_counter: Addr, pc: PathConstraint) -> None:
        """
        Add a branch to our covered branches list. Each branch is encoded according
        to the coverage strategy. For code coverage, the branch encoding is the
        address of the instruction. For edge coverage, the branch encoding is the
        tupe (src address, dst address). For path coverage, the branch encoding
        is the MD5 of the conjunction of all taken branch addresses.

        :param program_counter: The address of the branch instruction
        :param pc: Information of the branch condition and its constraints
        :return: None
        """

        if pc.isMultipleBranches():
            # Retrieve both branches
            branches = pc.getBranchConstraints()
            taken, not_taken = branches if branches[0]['isTaken'] else branches[::-1]
            taken_addr, not_taken_addr = taken['dstAddr'], not_taken['dstAddr']

            if self.strategy == CoverageStrategy.CODE_COVERAGE:
                if not_taken_addr not in self.instructions:  # Keep the address that has not been covered (and could have)
                    self.not_instructions.add(not_taken_addr)

            if self.strategy == CoverageStrategy.EDGE_COVERAGE:
                taken_tuple, not_taken_tuple = (program_counter, taken_addr), (program_counter, not_taken_addr)
                self.edges[taken_tuple] += 1
                self.not_edges.discard(taken_tuple)    # Remove it from non-taken if it was inside
                if not_taken_tuple not in self.edges:  # Add the not taken tuple in non-covered
                    self.not_edges.add(not_taken_tuple)

            if self.strategy == CoverageStrategy.PATH_COVERAGE:
                self.current_path.append(taken_addr)

                # Compute the hash of the not taken path and add it to non-covered paths
                not_taken_path_hash = self.current_path_hash.copy()
                not_taken_path_hash.update(struct.pack('<Q', not_taken_addr))
                self.not_paths.add(not_taken_path_hash.hexdigest())

                # Update the current path hash and add it to hashes
                self.current_path_hash.update(struct.pack("<Q", taken_addr))
                self.paths.add(self.current_path_hash.hexdigest())

        else:
            pass  # TODO: Maybe something to do one jmp rax & Co


    @property
    def unique_instruction_covered(self) -> int:
        """
        :return: The number of unique instructions covered
        """
        return len(self.instructions)


    @property
    def unique_edge_covered(self) -> int:
        """
        :return: The number of unique edges covered
        """
        return len(self.edges)


    @property
    def total_instruction_executed(self) -> int:
        """
        :return: The number of total instruction executed
        """
        return sum(self.instructions.values())


    def post_execution(self) -> None:
        """
        This function is called after each execution.

        :return: None
        """
        pass


    def is_covered(self, item: CovItem) -> bool:
        """
        Return whether the item has been covered or not

        :param item: An address, an edge or a path
        :return: bool
        """
        if self.strategy == CoverageStrategy.CODE_COVERAGE:
            return item in self.instructions
        if self.strategy == CoverageStrategy.EDGE_COVERAGE:
            return item in self.edges
        if self.strategy == CoverageStrategy.PATH_COVERAGE:
            return item in self.paths


    def pp_item(self, covitem: CovItem) -> str:
        """
        Pretty print a CovItem according the coverage strategy

        :param covitem: An address, an edge or a path
        :return: str
        """
        if self.strategy == CoverageStrategy.CODE_COVERAGE:
            return f"0x{covitem:08x}"
        elif self.strategy == CoverageStrategy.EDGE_COVERAGE:
            return f"(0x{covitem[0]:08x} -> 0x{covitem[1]:08x})"
        elif self.strategy == CoverageStrategy.PATH_COVERAGE:
            return covitem  # already a hash str



class GlobalCoverage(CoverageSingleRun):
    """
    This class is used to represent the coverage of an execution.
    """

    INSTRUCTION_COVERAGE_FILE = "instruction_coverage.json"
    EDGE_COVERAGE_FILE = "edge_coverage.json"
    PATH_COVERAGE_FILE = "path_coverage.json"

    def __init__(self, strategy: CoverageStrategy, workspace: Workspace, branch_strategy: BranchCheckStrategy):
        super().__init__(strategy)
        self.workspace = workspace
        self.branch_strategy = branch_strategy

        # Load the coverage from the workspace (if it exists)
        self.load_coverage()

        # Keep pending items to be covered (code, edge, path)
        self.pending_coverage = set()


    def iter_new_paths(self, path_constraints: List[PathConstraint]) -> Generator[Tuple[List[PathConstraint], PathBranch, CovItem], Solver, None]:
        """
        The function iterate the given path predicate and yield PatchConstraint to
        consider as-is and PathBranch representing the new branch to take. It acts
        as a black-box so that the SeedManager does not have to know what strategy
        is being used under the hood. From an impementation perspective the goal
        of the function is to manipulate the path WITHOUT doing any SMT related things.

        .. todo:: Need to implement strategies for a given target returning, all
           occurences, only the first, only the last etc. At the moment only the first.

        :param path_constraints: list of path constraint to iterate
        :return: generator of path constraint and branches to solve. The first tuple
        item is a list of PathConstraint to add in the path predicate and the second
        is the branch to solve (but not to keep in path predicate)
        """
        pending_csts = []
        current_hash = hashlib.md5()  # Current path hash for PATH coverage

        occurence_map = self._get_occurence_map(path_constraints)
        is_ok_with_branch_strategy = lambda covitem, idx: True if self.strategy == CoverageStrategy.PATH_COVERAGE else (idx in occurence_map[covitem])


        for i, pc in enumerate(path_constraints):         # Iterate through all path constraints
            if pc.isMultipleBranches():     # If there is a condition
                for branch in pc.getBranchConstraints():  # Get all branches
                    # Get the constraint of the branch which has not been taken.
                    if not branch['isTaken']:
                        src, dst = branch['srcAddr'], branch['dstAddr']

                        # Check if the target is new with regards to the strategy
                        if self.strategy == CoverageStrategy.CODE_COVERAGE:
                            item = dst
                            new = item not in self.instructions and item not in self.pending_coverage

                        elif self.strategy == CoverageStrategy.EDGE_COVERAGE:
                            item = (src, dst)
                            new = item not in self.edges and item not in self.pending_coverage

                        elif self.strategy == CoverageStrategy.PATH_COVERAGE:
                            # Have to fork the hash of the current pc for each branch we want to revert
                            forked_hash = current_hash.copy()
                            forked_hash.update(struct.pack("<Q", dst))
                            item = forked_hash.hexdigest()
                            new = item not in self.paths and item not in self.pending_coverage
                        else:
                            assert False

                        # If the not taken branch is new wrt coverage
                        if new and is_ok_with_branch_strategy(item, i):
                            res = yield pending_csts, branch, item
                            if res == Solver.SAT:  # If path was satisfiable add it to pending coverage
                                self.pending_coverage.add(item)

                            pending_csts = []  # reset pending constraint added

                    else:
                        pass  # Branch was taken do nothing
            else:
                pass  # TODO: trying to enumerate values for jmp rax etc ..

            # Add it the path preodicate constraints and update current path hash
            pending_csts.append(pc)
            current_hash.update(struct.pack("<Q", pc.getTakenAddress()))


    def _get_occurence_map(self, path_constraints: List[PathConstraint]) -> Dict[CovItem, List[int]]:
        """ For a list of path constraints, compute the offset of occurence of each item in the list """
        map = {}
        for i, pc in enumerate(path_constraints):
            if pc.isMultipleBranches():     # If there is a condition
                for branch in pc.getBranchConstraints():  # Get all branches
                    if not branch['isTaken']:
                        src, dst = branch['srcAddr'], branch['dstAddr']
                        if self.strategy == CoverageStrategy.CODE_COVERAGE:
                            item = dst
                        elif self.strategy == CoverageStrategy.EDGE_COVERAGE:
                            item = (src, dst)
                        else: # Do nothing for PATH_COVERAGE strategy as all items will be new ones
                            continue
                        if item in map:
                            map[item].append(i)
                        else:
                            map[item] = [i]
                    else:
                        pass  # Not interested by the taken branch
            else:
                pass  # TODO: trying to enumerate values for jmp rax etc ..

        # Now filter the map according to the branch solving strategy
        if self.branch_strategy == BranchCheckStrategy.FIRST_LAST_NOT_COVERED:
            for k in map.keys():
                l = map[k]
                if len(l) > 2:
                    map[k] = [l[0], l[-1]]  # Only keep first and last iteration
        return map


    def merge(self, other: CoverageSingleRun) -> None:
        """
        Merge a CoverageSingeRun instance into this instance

        :param other: The CoverageSingleRun to merge into our GlobalCoverage instance
        :return: None
        """
        assert self.strategy == other.strategy

        # Update instruction coverage for code coverage (in all cases keep code coverage)
        self.instructions.update(other.instructions)

        # Update pending
        if self.strategy == CoverageStrategy.CODE_COVERAGE:
            self.pending_coverage.difference_update(other.instructions)

        # Update instruction coverage for edge
        if self.strategy == CoverageStrategy.EDGE_COVERAGE:
            self.edges.update(other.edges)
            self.pending_coverage.difference_update(other.edges)

        # Update instruction coverage for path constraints
        if self.strategy == CoverageStrategy.PATH_COVERAGE:
            self.paths.update(other.paths)
            self.pending_coverage.difference_update(other.paths)


    def can_improve_coverage(self, other: CoverageSingleRun) -> bool:
        """
        Check if some off the non-covered are not already in the global coverage

        :param other: The CoverageSingleRun to check with our global coverage state
        :return: bool
        """
        return bool(self.new_items_to_cover(other))


    def new_items_to_cover(self, other: CoverageSingleRun) -> Set[CovItem]:
        """
        Return all addreses, edges, paths that the given CoverageSingleRun
        can cover if we invert their branches

        :param other: The CoverageSingleRun to check with our global coverage state
        :return: A set of CovItem
        """
        assert self.strategy == other.strategy
        if self.strategy == CoverageStrategy.CODE_COVERAGE:
            return other.not_instructions - self.instructions.keys()
        elif self.strategy == CoverageStrategy.EDGE_COVERAGE:
            return other.not_edges - self.edges.keys()
        elif self.strategy == CoverageStrategy.PATH_COVERAGE:
            return other.not_paths - self.paths


    def save_coverage(self) -> None:
        """
        Save the coverage in the workspace

        :return: None
        """
        # Save instruction coverage
        if self.instructions:
            self.workspace.save_metadata_file(self.INSTRUCTION_COVERAGE_FILE, json.dumps(self.instructions, indent=2))

        # Save edge coverage
        if self.edges:
            self.workspace.save_metadata_file(self.EDGE_COVERAGE_FILE, json.dumps([[list(k), v] for k, v in self.edges.items()], indent=2))

        # Save path coverage
        if self.paths:
            self.workspace.save_metadata_file(self.PATH_COVERAGE_FILE, json.dumps(list(self.paths)))


    def load_coverage(self) -> None:
        """
        Load the coverage from the workspace

        :return: None
        """
        # Load instruction coverage
        data = self.workspace.get_metadata_file(self.INSTRUCTION_COVERAGE_FILE)
        if data:
            logging.debug(f"Loading the existing instruction coverage from: {self.INSTRUCTION_COVERAGE_FILE}")
            self.instructions = Counter(json.loads(data))

        # Load instruction edge
        data = self.workspace.get_metadata_file(self.EDGE_COVERAGE_FILE)
        if data:
            logging.debug(f"Loading the existing edge coverage from: {self.EDGE_COVERAGE_FILE}")
            self.edges = Counter({tuple(x[0]): x[1] for x in json.loads(data)})

        # Load path coverage
        data = self.workspace.get_metadata_file(self.PATH_COVERAGE_FILE)
        if data:
            logging.debug(f"Loading the existing path coverage from: {self.PATH_COVERAGE_FILE}")
            self.paths = set(json.loads(data))


    def post_exploration(self) -> None:
        """ Function called at the very end of the exploration """
        self.save_coverage()
