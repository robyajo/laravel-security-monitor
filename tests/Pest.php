<?php

use Internal\SecurityMonitor\Tests\TestCase;

// Pest 3+ exposes the `pest()` helper; Pest 2 (used by Laravel 10 /
// Orchestra Testbench 8) only provides `uses()`.
if (function_exists('pest')) {
    pest()->extend(TestCase::class)->in('Feature');
} else {
    uses(TestCase::class)->in('Feature');
}
