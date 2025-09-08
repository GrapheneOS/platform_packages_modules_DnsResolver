/**
 * Copyright (c) 2025, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.resolv.aidl;

/**
 * DNS forwarding configuration parameters for upstream network.
 *
 * @hide
 */

@JavaDerive(equals=true, toString=true)
parcelable DnsForwardingParamsParcel {
    /** The network ID of the upstream network for sending DNS queries. */
    int netId;

    /**
    * The UID on behalf of which to forward DNS packets received on this interface.
    * (e.g., AID_DNS_TETHER for normal tethering traffic).
    */
    int uid;
}