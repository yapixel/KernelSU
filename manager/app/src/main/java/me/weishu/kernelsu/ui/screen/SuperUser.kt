package me.weishu.kernelsu.ui.screen

import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.pullToRefresh
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.AppProfileScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.result.ResultRecipient
import kotlinx.coroutines.launch
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ui.component.ExpressiveLazyList
import me.weishu.kernelsu.ui.component.ExpressiveListItem
import me.weishu.kernelsu.ui.component.SearchAppBar
import me.weishu.kernelsu.ui.viewmodel.SuperUserViewModel

@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
@Destination<RootGraph>
@Composable
fun SuperUserScreen(
    navigator: DestinationsNavigator,
    appProfileResultRecipient: ResultRecipient<AppProfileScreenDestination, Boolean>
) {
    val viewModel = viewModel<SuperUserViewModel>()
    val scope = rememberCoroutineScope()
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val listState = rememberLazyListState()
    val pullToRefreshState = rememberPullToRefreshState()

    LaunchedEffect(key1 = navigator) {
        if (viewModel.appList.isEmpty()) {
            viewModel.fetchAppList()
        }
    }

    appProfileResultRecipient.onNavResult {
        scope.launch {
            viewModel.fetchAppList()
        }
    }
    
    val onRefresh: () -> Unit = {
        scope.launch { 
            viewModel.fetchAppList()
        }
    }
    
    val scaleFraction = {
        if (viewModel.isRefreshing) 1f
        else LinearOutSlowInEasing.transform(pullToRefreshState.distanceFraction).coerceIn(0f, 1f)
    }

    Scaffold(
        modifier = Modifier.pullToRefresh(
            state = pullToRefreshState,
            isRefreshing = viewModel.isRefreshing,
            onRefresh = onRefresh,
        ),
        topBar = {
            SearchAppBar(
                title = { Text(stringResource(R.string.superuser)) },
                searchText = viewModel.search,
                onSearchTextChange = { viewModel.search = it },
                onClearClick = { viewModel.search = TextFieldValue("") },
                dropdownContent = {
                    var showDropdown by remember { mutableStateOf(false) }

                    IconButton(
                        onClick = { showDropdown = true },
                    ) {
                        Icon(
                            imageVector = Icons.Filled.MoreVert,
                            contentDescription = stringResource(id = R.string.settings)
                        )

                        DropdownMenu(expanded = showDropdown, onDismissRequest = {
                            showDropdown = false
                        }) {
                            DropdownMenuItem(text = {
                                Text(stringResource(R.string.refresh))
                            }, onClick = {
                                scope.launch {
                                    viewModel.fetchAppList()
                                    listState.scrollToItem(0)
                                }
                                showDropdown = false
                            })
                            DropdownMenuItem(text = {
                                Text(
                                    if (viewModel.showSystemApps) {
                                        stringResource(R.string.hide_system_apps)
                                    } else {
                                        stringResource(R.string.show_system_apps)
                                    }
                                )
                            }, onClick = {
                                viewModel.updateShowSystemApps(!viewModel.showSystemApps)
                                showDropdown = false
                            })
                        }
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Box(Modifier.padding(innerPadding)) {
            val appList = viewModel.appList
            ExpressiveLazyList(
                modifier = Modifier
                    .fillMaxSize()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                items = appList,
                itemContent = { app ->
                    AppItem(app) {
                        navigator.navigate(AppProfileScreenDestination(app))
                    }
                }
            )
            Box(
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .graphicsLayer {
                        scaleX = scaleFraction()
                        scaleY = scaleFraction()
                    }
            ) {
                PullToRefreshDefaults.LoadingIndicator(state = pullToRefreshState, isRefreshing = viewModel.isRefreshing)
            }
        }
    }
}

@Composable
private fun AppItem(
    app: SuperUserViewModel.AppInfo,
    onClickListener: () -> Unit,
) {
    ExpressiveListItem(
        onClick = onClickListener,
        headlineContent = { Text(app.label) },
        supportingContent = { Text(app.packageName) },
        trailingContent = {
            Column(
                horizontalAlignment = Alignment.End
            ) {
                if (app.allowSu) {
                    LabelText(
                        label = "ROOT",
                        textColor = MaterialTheme.colorScheme.onPrimary,
                        backgroundColor = MaterialTheme.colorScheme.primary
                    )
                } else {
                    if (app.shouldUmount) {
                        LabelText(
                            label = "UMOUNT",
                            textColor = MaterialTheme.colorScheme.onSecondary,
                            backgroundColor = MaterialTheme.colorScheme.secondary
                        )
                    }
                }
                if (app.hasCustomProfile) {
                    LabelText(
                        label = "CUSTOM",
                        textColor = MaterialTheme.colorScheme.onSecondaryContainer,
                        backgroundColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                }
                val userId = app.uid / 100000
                if (userId != 0) {
                    LabelText(
                        label = "UID$userId",
                        textColor = MaterialTheme.colorScheme.onTertiary,
                        backgroundColor = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
        },
        leadingContent = {
            AsyncImage(
                model = ImageRequest.Builder(LocalContext.current)
                    .data(app.packageInfo)
                    .crossfade(true)
                    .build(),
                contentDescription = app.label,
                modifier = Modifier
                    .width(48.dp)
                    .height(48.dp)
            )
        },
    )
}

@Composable
fun LabelText(
    label: String,
    textColor: Color = MaterialTheme.colorScheme.onPrimary,
    backgroundColor: Color = MaterialTheme.colorScheme.primary
) {
    Box(
        modifier = Modifier
            .padding(vertical = 2.dp, horizontal = 2.dp)
            .background(
                color = backgroundColor,
                shape = RoundedCornerShape(4.dp)
            )
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(vertical = 2.dp, horizontal = 5.dp),
            style = TextStyle(
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                color = textColor,
            )
        )
    }
}
