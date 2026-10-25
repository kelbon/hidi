#include "hidi/utils/merged_segments.hpp"

#include <iostream>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <random>

#define error_if(...)                          \
  if ((__VA_ARGS__)) {                         \
    std::cout << "ERROR ON LINE " << __LINE__; \
    std::exit(__LINE__);                       \
  }

struct primitive_merged_segments {
  std::unordered_set<intmax_t> us;

  void add_point(intmax_t point) {
    us.insert(point);
  }

  bool has_point(intmax_t point) const noexcept {
    return us.contains(point);
  }
};

struct node {
  node* next;
  int i;

  node(int i) : i(i) {
  }
};

int main() {
  const int MIN_POINT = 1;
  const int MAX_POINT = 10000;

  hidi::merged_segments ms;
  primitive_merged_segments pms;

  // tests points [1, 2, ... MAX_POINT]
  std::vector<int> points;
  for (int i = MIN_POINT; i <= MAX_POINT; ++i)
    points.push_back(i);

  std::mt19937 g(1122);
  auto dist = std::uniform_int_distribution<size_t>(0, points.size() - 1);
  std::shuffle(points.begin(), points.end(), g);

  for (auto x : points)
    error_if(ms.has_point(x));

  for (auto point : points) {
    ms.add_point(point);
    pms.add_point(point);
    error_if(!ms.has_point(point));
    auto randomp = points[dist(g)];
    error_if(ms.has_point(randomp) != pms.has_point(randomp));
  }

  for (int i = MIN_POINT; i <= MAX_POINT; ++i)
    error_if(!ms.has_point(i));

  error_if(ms.segments_count() != 1);

  // add_segment сливается с пересекающимися и соседними отрезками
  {
    hidi::merged_segments s;
    s.add_point(0);
    s.add_point(10);
    s.add_point(20);
    s.add_segment(2, 8);
    error_if(s.segments_count() != 4);
    error_if(s.has_point(1) || !s.has_point(2) || !s.has_point(8) || s.has_point(9));
    s.add_segment(1, 9);  // соединяет [0], [2, 8], [10]
    error_if(s.segments_count() != 2);
    s.add_segment(11, 19);
    error_if(s.segments_count() != 1);
    for (int i = 0; i <= 20; ++i)
      error_if(!s.has_point(i));
    error_if(s.has_point(-1) || s.has_point(21));
  }

  return 0;
}
