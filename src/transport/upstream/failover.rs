use super::*;

impl UpstreamManager {
    /// Connect once per eligible upstream, retaining the successful route's egress identity.
    pub(super) async fn connect_failover(
        &self,
        target: SocketAddr,
        dc_idx: Option<i16>,
        scope: Option<&str>,
        probe: bool,
    ) -> Result<(UpstreamStream, UpstreamEgressInfo)> {
        let started = Instant::now();
        // Health orders candidates, but never removes the last recovery path.
        // Configuration order is the priority within each health tier.
        let candidates = {
            let states = self.upstreams.read().await;
            let mut indices: Vec<usize> = states.iter().enumerate()
                .filter(|(_, state)| scope.map_or(state.config.scopes.is_empty(), |s| {
                    state.config.scopes.split(',').any(|value| value.trim() == s)
                }))
                .map(|(idx, _)| idx)
                .collect();
            indices.sort_by_key(|&idx| !states[idx].healthy);
            indices
        };
        let mut last_error = ProxyError::Config("No upstreams available".to_string());
        let mut attempts = 0u32;
        for idx in candidates.into_iter().take(self.connect_retry_attempts as usize) {
            let remaining = self.connect_budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                last_error = ProxyError::ConnectionTimeout { addr: target.to_string() };
                break;
            }
            let (mut config, bind_rr, preference) = {
                let states = self.upstreams.read().await;
                let state = &states[idx];
                (state.config.clone(), Some(state.bind_rr.clone()),
                    dc_idx.and_then(UpstreamState::dc_array_idx)
                        .map(|di| state.dc_ip_pref[di]).unwrap_or(IpPreference::Unknown))
            };
            if let Some(s) = scope {
                config.selected_scope = s.to_string();
            }
            // Resolve each candidate from the original target: IP-family preferences differ.
            let candidate_target = if dc_idx.is_some() {
                match Self::resolve_runtime_dc_target(target, dc_idx, &config, preference) {
                    Ok(value) => value,
                    Err(error) => { last_error = error; continue; }
                }
            } else { target };
            let timeout = remaining.min(Duration::from_secs(self.tg_connect_timeout_secs));
            attempts += 1;
            self.stats.increment_upstream_connect_attempt_total();
            let attempt_started = Instant::now();
            // Cover the entire dial, including DNS, proxy TCP and SOCKS negotiation.
            let operation = async {
                let (mut stream, egress) = self.connect_via_upstream(
                    idx, &config, candidate_target, bind_rr.clone(), timeout).await?;
                if probe {
                    telegram_probe(&mut stream).await?;
                    // Never reuse the probe's protocol state for the user's encrypted session.
                    drop(stream);
                    self.connect_via_upstream(idx, &config, candidate_target, bind_rr, timeout).await
                } else {
                    Ok((stream, egress))
                }
            };
            let result = tokio::time::timeout(timeout, operation).await;
            let result = result.unwrap_or_else(|_| Err(ProxyError::ConnectionTimeout {
                addr: candidate_target.to_string(),
            }));
            match result {
                Ok((stream, egress)) => {
                    let mut states = self.upstreams.write().await;
                    let state = &mut states[idx];
                    state.healthy = true;
                    state.fails = 0;
                    if let Some(di) = dc_idx.and_then(UpstreamState::dc_array_idx) {
                        state.dc_latency[di].update(attempt_started.elapsed().as_secs_f64() * 1000.0);
                    }
                    self.stats.increment_upstream_connect_success_total();
                    self.stats.observe_upstream_connect_attempts_per_request(attempts);
                    self.stats.observe_upstream_connect_duration_ms(started.elapsed().as_millis() as u64, true);
                    return Ok((stream, egress));
                }
                Err(error) => {
                    // A permanent error on one route must not suppress a distinct reserve.
                    let mut states = self.upstreams.write().await;
                    let state = &mut states[idx];
                    state.fails = state.fails.saturating_add(1);
                    if state.fails >= self.unhealthy_fail_threshold {
                        state.healthy = false;
                    }
                    warn!(upstream = idx, attempt = attempts, error = %error,
                        "Upstream connect failed; trying next distinct route");
                    last_error = error;
                }
            }
            let remaining = self.connect_budget.saturating_sub(started.elapsed());
            let backoff = self.retry_backoff_with_jitter().min(remaining);
            if !backoff.is_zero() && attempts < self.connect_retry_attempts {
                tokio::time::sleep(backoff).await;
            }
        }
        self.stats.increment_upstream_connect_fail_total();
        self.stats.observe_upstream_connect_attempts_per_request(attempts);
        self.stats.observe_upstream_connect_duration_ms(started.elapsed().as_millis() as u64, false);
        Err(last_error)
    }
}

/// Verify a bounded unauthenticated MTProto exchange, without user data or credentials.
async fn telegram_probe<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let nonce: [u8; 16] = rand::rng().random();
    let mut request = Vec::with_capacity(48);
    request.extend_from_slice(&[0xee; 4]);
    request.extend_from_slice(&40u32.to_le_bytes());
    request.extend_from_slice(&[0; 8]);
    let message_id = (chrono::Utc::now().timestamp() as u64) << 32;
    request.extend_from_slice(&message_id.to_le_bytes());
    request.extend_from_slice(&20u32.to_le_bytes());
    request.extend_from_slice(&0xbe7e8ef1u32.to_le_bytes());
    request.extend_from_slice(&nonce);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_le_bytes(length) as usize;
    if !(40..=4096).contains(&length) {
        return Err(ProxyError::InvalidHandshake("Invalid Telegram probe frame length".into()));
    }
    let mut response = vec![0; length];
    stream.read_exact(&mut response).await?;
    if response[..8] != [0; 8] || response[20..24] != 0x05162463u32.to_le_bytes()
        || response[24..40] != nonce
    {
        return Err(ProxyError::InvalidHandshake("Telegram probe response/nonce mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
