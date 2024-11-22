#pragma once

#include "params.h"
#include "poly.h"
#include <stdint.h>

void cbd_eta1(poly * r, const uint8_t * buf, size_t eta1);

void cbd_eta2(poly * r, const uint8_t buf[ML_ETA2 * ML_N / 4]);
