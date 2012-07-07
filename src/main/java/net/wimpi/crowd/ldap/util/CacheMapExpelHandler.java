/***
 * Coalevo Project
 * http://www.coalevo.net
 *
 * (c) Dieter Wimberger
 * http://dieter.wimpi.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at:
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ***/
package net.wimpi.crowd.ldap.util;

import java.util.Map;

/**
 * Provides the means for handling entries
 * when being expelled from the cache.
 * <p/>
 *
 * @author Dieter Wimberger (wimpi)
 * @version 1.0.0 (12/02/2011)
 */
public interface CacheMapExpelHandler<T1, T2> {

  /**
   * Called when an entry is expelled.
   *
   * @param entry the entry that has been expelled.
   */
  public void expelled(Map.Entry<T1, T2> entry);

}//interface CacheMapExpelHandler
