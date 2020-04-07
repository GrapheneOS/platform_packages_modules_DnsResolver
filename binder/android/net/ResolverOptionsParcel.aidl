/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net;

import android.net.ResolverHostsParcel;

/**
 * Knobs for OEM to control alternative behavior.
 *
 * {@hide}
 */
parcelable ResolverOptionsParcel {
    /**
     * An IP/hostname mapping table for DNS local lookup customization.
     * WARNING: this is intended for local testing and other special situations.
     * Future versions of the DnsResolver module may break your assumptions.
     * Injecting static mappings for public hostnames is generally A VERY BAD IDEA,
     * since it makes it impossible for the domain owners to migrate the domain.
     * It is also not an effective domain blocking mechanism, because apps can
     * easily hardcode IPs or bypass the system DNS resolver.
     */
    ResolverHostsParcel[] hosts = {};

    /**
     * Truncated UDP DNS response handling mode. Handling of UDP responses with the TC (truncated)
     * bit set. The values are defined in {@code IDnsResolver.aidl}
     * 0: TC_MODE_DEFAULT
     * 1: TC_MODE_UDP_TCP
     * Other values are invalid.
     */
    int tcMode = 0;
}
