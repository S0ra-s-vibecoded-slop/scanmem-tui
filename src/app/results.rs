//! The scan-results table.

use super::move_table_selection;
use crate::datatype::DataType;
use crate::memio::MemIo;
use crate::scanmem::Match;
use ratatui::widgets::TableState;

/// Most matches pulled from scanmem into the table after a scan.
pub const MAX_RESULTS: usize = 2000;

/// Rows below the visible ones that are kept fresh too, so scrolling feels instant.
const LIVE_LOOKAHEAD: usize = 2;

pub struct ResultRow {
    pub m: Match,
    /// The type this address is read and saved as.
    pub ty: DataType,
    /// Live value read straight from the process.
    pub live: Option<String>,
}

impl ResultRow {
    fn new(m: Match, scan_type: DataType) -> ResultRow {
        let ty = if m.types.contains(&scan_type) {
            scan_type
        } else {
            m.types.first().copied().unwrap_or(scan_type)
        };
        ResultRow { m, ty, live: None }
    }
}

pub struct Results {
    pub rows: Vec<ResultRow>,
    pub state: TableState,
    /// Matches scanmem reports in total; can exceed `rows.len()`.
    pub total: u64,
    /// Rows visible in the table; set by the renderer.
    pub viewport: usize,
}

impl Results {
    pub fn new() -> Results {
        Results {
            rows: Vec::new(),
            state: TableState::default(),
            total: 0,
            viewport: 20,
        }
    }

    pub fn clear(&mut self) {
        *self = Results {
            viewport: self.viewport,
            ..Results::new()
        };
    }

    pub fn replace(
        &mut self,
        matches: Vec<Match>,
        reported_count: Option<u64>,
        scan_type: DataType,
    ) {
        let shown = matches.len() as u64;
        let capped = matches.len() >= MAX_RESULTS;
        self.total = match reported_count {
            Some(count) => count,
            None if capped => self.total.max(shown),
            None => shown,
        };
        self.rows = matches
            .into_iter()
            .map(|m| ResultRow::new(m, scan_type))
            .collect();
        self.state = TableState::default();
        if !self.rows.is_empty() {
            self.state.select(Some(0));
        }
    }

    pub fn is_truncated(&self) -> bool {
        self.total > self.rows.len() as u64
    }

    pub fn selected(&self) -> Option<&ResultRow> {
        self.state.selected().and_then(|i| self.rows.get(i))
    }

    pub fn move_selection(&mut self, delta: isize) {
        move_table_selection(&mut self.state, self.rows.len(), delta);
    }

    /// Re-reads the rows on screen; says whether any value changed.
    pub fn refresh_live(&mut self, memory: Option<&MemIo>) -> bool {
        let first = self.state.offset().min(self.rows.len());
        let last = (first + self.viewport + LIVE_LOOKAHEAD).min(self.rows.len());
        let mut changed = false;
        for row in &mut self.rows[first..last] {
            let fresh = memory.and_then(|mem| mem.read_as(row.m.addr, row.ty));
            changed |= fresh != row.live;
            row.live = fresh;
        }
        changed
    }
}
