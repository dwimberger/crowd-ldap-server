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

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Provides a simple LRU cache map.
 * <p/>
 * When the caches ceiling is reached, the item
 * accessed longest ago will be removed.
 * The implementation is basically a small extension of functionality
 * that is already available through {@link java.util.LinkedHashMap}.
 * <p/>
 * If multiple threads access this cache concurrently,
 * it must be synchronized externally using:
 * </p>
 * <pre>
 *    Map m = Collections.synchronizedMap(new LRUCache(int size));
 * </pre>
 *
 * @author Dieter Wimberger (wimpi)
 * @version 1.0.0 (12/02/2011)
 */
public class LRUCacheMap<T1, T2> extends LinkedHashMap<T1, T2> {

  protected int m_Ceiling;
  protected CacheMapExpelHandler<T1, T2> m_ExpelHandler;

  public LRUCacheMap(int ceiling) {
    super((int) (ceiling * 1.25f), 0.75f, true);
    m_Ceiling = ceiling;
  }//size

  public void setExpelHandler(CacheMapExpelHandler<T1, T2> expelHandler) {
    m_ExpelHandler = expelHandler;
  }//setExpelHandler

  /**
   * Clears this <tt>LRUCacheMap</tt>.
   *
   * @param b if true, inform the {@link CacheMapExpelHandler}.
   */
  public void clear(boolean b) {
    if (b && m_ExpelHandler != null) {
      synchronized (this) {
        //remove eldest
        for (Iterator<Map.Entry<T1, T2>> iterator = entrySet().iterator(); iterator.hasNext();) {
          Map.Entry<T1, T2> entry = iterator.next();
          iterator.remove();
          m_ExpelHandler.expelled(entry);
        }
      }
    } else {
      clear();
    }
  }//clear

  protected boolean removeEldestEntry(Map.Entry<T1, T2> eldest) {
    boolean b = size() > m_Ceiling;
    try {
      return b;
    } finally {
      if (m_ExpelHandler != null && b) {
        m_ExpelHandler.expelled(eldest);
      }
    }
  }//removeEldestEntry

  /**
   * Returns the maximum number instances this cache can hold.
   *
   * @return the maximum number instances this cache can hold.
   */
  public int getCeiling() {
    return m_Ceiling;
  }//getCeiling

  /**
   * Sets the maximum number of instances this cache can hold,
   * either by allowing it grow further in the future,
   * or by automagically shrinking it discarding the eldest cache
   * entries.
   *
   * @param size the maximum number of instances this cache should hold.
   */
  public void setCeiling(int size) {
    if (size == m_Ceiling) {
      return;
    } else if (size > m_Ceiling) {
      m_Ceiling = size;
    } else {
      synchronized (this) {
        //remove eldest
        for (Iterator<Map.Entry<T1, T2>> iterator = entrySet().iterator(); iterator.hasNext();) {
          if (size() > size) {
            Map.Entry<T1, T2> entry = iterator.next();
            iterator.remove();
            if (m_ExpelHandler != null) {
              m_ExpelHandler.expelled(entry);
            }
          } else {
            break;
          }
        }
      }
      m_Ceiling = size;
    }
  }//setCeiling

  public String toString() {
    final StringBuilder sbuf = new StringBuilder();
    synchronized (this) {
      for (Iterator<Map.Entry<T1, T2>> iterator = entrySet().iterator(); iterator.hasNext();) {
        Map.Entry<T1, T2> entry = iterator.next();
        sbuf.append(entry.getKey());
        sbuf.append(" = ");
        sbuf.append(entry.getValue());
        sbuf.append("\n");
      }
    }
    return sbuf.toString();

  }//toString

}//class LRUCacheMap
